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
                        CHECK (status IN ('active','completed','failed','stopped')),
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
