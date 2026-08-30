-- Create agent_sessions and agent_messages tables
-- For Phase 3 - Autogen multi-agent system

-- ===============================
-- agent_sessions table
-- ===============================
CREATE TABLE IF NOT EXISTS public.agent_sessions (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_name        text NOT NULL,
    target_description  text NOT NULL,
    status              text NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','completed','failed','stopped','stalled','awaiting_approval')),
    configuration       jsonb DEFAULT '{}'::jsonb,  -- Agent configuration
    summary             text,  -- Final summary of the session
    metadata            jsonb DEFAULT '{}'::jsonb,  -- Additional metadata
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    end_time            timestamptz
);

CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON public.agent_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_created_at ON public.agent_sessions(created_at DESC);

-- ===============================
-- agent_messages table
-- ===============================
CREATE TABLE IF NOT EXISTS public.agent_messages (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id  uuid NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
    agent_name  text NOT NULL,  -- Name of the agent (Coordinator, Scanner, Analyzer, etc.)
    role        text NOT NULL,  -- 'system', 'user', 'assistant', 'function'
    content     text NOT NULL,  -- Message content
    metadata    jsonb DEFAULT '{}'::jsonb,  -- Function calls, tool results, etc.
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_messages_session_id ON public.agent_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_messages_agent_name ON public.agent_messages(agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_messages_created_at ON public.agent_messages(created_at DESC);

-- ===============================
-- Triggers for updated_at
-- ===============================
-- Ensure the _touch_updated_at function exists
CREATE OR REPLACE FUNCTION public._touch_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- agent_sessions trigger
DROP TRIGGER IF EXISTS trg_agent_sessions_updated_at ON public.agent_sessions;
CREATE TRIGGER trg_agent_sessions_updated_at
    BEFORE UPDATE ON public.agent_sessions
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ===============================
-- Grant permissions
-- ===============================
GRANT ALL PRIVILEGES ON public.agent_sessions TO app;
GRANT ALL PRIVILEGES ON public.agent_messages TO app;

-- ===============================
-- Security tests (agent-created, re-runnable proof records)
-- ===============================
-- Canonical DDL lives in ensure_all_tables.sql; mirrored here because these are
-- agent-owned objects that reference agent_sessions. Keep the two in sync.
CREATE TABLE IF NOT EXISTS public.security_tests (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL,
    description           text,
    tier                  text NOT NULL DEFAULT 'safe' CHECK (tier IN ('safe','impactful')),
    category              text,
    target_ip             inet,
    target_host           text,
    target_port           integer,
    target_service        text,
    command               text,
    tool                  text,
    assertion             jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_finding_source text,
    source_finding_id     uuid,
    attack_vector_id      uuid,
    pending_exploit_id    uuid,
    created_by_session    uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
    engagement_id         uuid,
    enabled               boolean NOT NULL DEFAULT true,
    last_run_at           timestamptz,
    last_run_status       text CHECK (last_run_status IN ('pass','fail','error','skipped')),
    run_count             integer NOT NULL DEFAULT 0,
    metadata              jsonb DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_tests_lane_ck CHECK (
        (tier = 'impactful' AND pending_exploit_id IS NOT NULL)
        OR (tier = 'safe' AND command IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_security_tests_session ON public.security_tests(created_by_session);
CREATE INDEX IF NOT EXISTS idx_security_tests_tier    ON public.security_tests(tier);

CREATE TABLE IF NOT EXISTS public.security_test_runs (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id              uuid NOT NULL REFERENCES public.security_tests(id) ON DELETE CASCADE,
    ran_at               timestamptz NOT NULL DEFAULT now(),
    completed_at         timestamptz,
    duration_ms          integer,
    status               text NOT NULL DEFAULT 'error' CHECK (status IN ('pass','fail','error','skipped')),
    lane                 text NOT NULL CHECK (lane IN ('safe','impactful')),
    command_run          text,
    exit_code            integer,
    result_summary       text,
    assertion_eval       jsonb DEFAULT '{}'::jsonb,
    tool_execution_id    uuid,
    exploit_result_id    uuid,
    triggered_by         text,
    triggered_by_session uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
    engagement_id        uuid,
    output               text,
    metadata             jsonb DEFAULT '{}'::jsonb,
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_security_test_runs_test ON public.security_test_runs(test_id, ran_at DESC);

DO $$ BEGIN
    CREATE TRIGGER trg_security_tests_updated_at
        BEFORE UPDATE ON public.security_tests
        FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

GRANT ALL PRIVILEGES ON public.security_tests     TO app;
GRANT ALL PRIVILEGES ON public.security_test_runs TO app;
