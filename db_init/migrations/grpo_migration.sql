-- grpo_migration.sql
-- GRPO (Group Relative Policy Optimization) training infrastructure tables
-- Run in the scans database alongside agent_sessions/agent_messages

\connect scans

-- ===============================
-- grpo_feedback table - stores (prompt, response, human_rating) tuples
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.grpo_feedback') IS NULL THEN
    CREATE TABLE public.grpo_feedback (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      task_type           text NOT NULL CHECK (task_type IN ('scan_analysis', 'exploit_recommendation', 'agent_decision')),
      user_prompt         text NOT NULL,
      model_response      text NOT NULL,
      system_prompt       text,
      context             jsonb DEFAULT '{}'::jsonb,

      -- Human rating
      rating              integer CHECK (rating BETWEEN 1 AND 5),
      rating_dimensions   jsonb DEFAULT '{}'::jsonb,  -- {accuracy, completeness, actionability}
      reviewer_id         text,
      review_notes        text,

      -- Session linkage
      session_id          uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
      agent_message_id    uuid REFERENCES public.agent_messages(id) ON DELETE SET NULL,

      -- Training pipeline tracking
      dataset_version     text,
      used_in_training    boolean DEFAULT false,

      created_at          timestamptz NOT NULL DEFAULT now(),
      updated_at          timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_grpo_feedback_task_type ON public.grpo_feedback(task_type);
    CREATE INDEX idx_grpo_feedback_rating ON public.grpo_feedback(rating);
    CREATE INDEX idx_grpo_feedback_session_id ON public.grpo_feedback(session_id);
    CREATE INDEX idx_grpo_feedback_dataset_version ON public.grpo_feedback(dataset_version);
    CREATE INDEX idx_grpo_feedback_used_in_training ON public.grpo_feedback(used_in_training);
    CREATE INDEX idx_grpo_feedback_created_at ON public.grpo_feedback(created_at DESC);
  END IF;
END$$;

-- ===============================
-- grpo_training_runs table - tracks each training run
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.grpo_training_runs') IS NULL THEN
    CREATE TABLE public.grpo_training_runs (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      base_model          text NOT NULL,
      dataset_version     text NOT NULL,
      task_types          text[] NOT NULL,
      hyperparameters     jsonb NOT NULL DEFAULT '{}'::jsonb,

      -- Run status
      status              text NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued', 'running', 'completed', 'failed')),
      error_message       text,

      -- Metrics
      metrics             jsonb DEFAULT '{}'::jsonb,  -- loss, reward curves, eval scores
      output_path         text,

      -- Tracking
      started_at          timestamptz,
      completed_at        timestamptz,
      created_at          timestamptz NOT NULL DEFAULT now(),
      updated_at          timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_grpo_training_runs_status ON public.grpo_training_runs(status);
    CREATE INDEX idx_grpo_training_runs_base_model ON public.grpo_training_runs(base_model);
    CREATE INDEX idx_grpo_training_runs_created_at ON public.grpo_training_runs(created_at DESC);
  END IF;
END$$;

-- ===============================
-- grpo_model_registry table - deployed model tracking + A/B config
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.grpo_model_registry') IS NULL THEN
    CREATE TABLE public.grpo_model_registry (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      model_name          text NOT NULL,
      model_format        text NOT NULL CHECK (model_format IN ('gguf', 'safetensors', 'lora')),
      model_path          text NOT NULL,
      base_model          text,

      -- Deployment config
      is_active           boolean DEFAULT false,
      ab_weight           numeric DEFAULT 0.0 CHECK (ab_weight >= 0.0 AND ab_weight <= 1.0),

      -- Evaluation metrics
      eval_metrics        jsonb DEFAULT '{}'::jsonb,

      -- Lineage
      training_run_id     uuid REFERENCES public.grpo_training_runs(id) ON DELETE SET NULL,

      created_at          timestamptz NOT NULL DEFAULT now(),
      updated_at          timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_grpo_model_registry_is_active ON public.grpo_model_registry(is_active);
    CREATE INDEX idx_grpo_model_registry_model_name ON public.grpo_model_registry(model_name);
    CREATE INDEX idx_grpo_model_registry_created_at ON public.grpo_model_registry(created_at DESC);
  END IF;
END$$;

-- ===============================
-- Triggers for updated_at columns
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.grpo_feedback') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_grpo_feedback_updated_at ON public.grpo_feedback;
    CREATE TRIGGER trg_grpo_feedback_updated_at
      BEFORE UPDATE ON public.grpo_feedback
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF to_regclass('public.grpo_training_runs') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_grpo_training_runs_updated_at ON public.grpo_training_runs;
    CREATE TRIGGER trg_grpo_training_runs_updated_at
      BEFORE UPDATE ON public.grpo_training_runs
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF to_regclass('public.grpo_model_registry') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_grpo_model_registry_updated_at ON public.grpo_model_registry;
    CREATE TRIGGER trg_grpo_model_registry_updated_at
      BEFORE UPDATE ON public.grpo_model_registry
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- Grant privileges
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scans;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scans;
