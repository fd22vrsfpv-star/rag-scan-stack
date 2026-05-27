-- setup_all_databases.sql
-- Single consolidated script for: n8n, exploitdb, scans
-- Run as a superuser in psql:
--   psql -v ON_ERROR_STOP=1 -f setup_all_databases.sql

-------------------------
-- GLOBAL (run in 'postgres' or any DB as superuser)
-------------------------
-- Note: CREATE DATABASE will fail if DB already exists. That's safe; subsequent statements connect.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";  -- helpful globally
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;
-- vector extension not always available; include if your Postgres has it
DO $$
BEGIN
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'vector extension not available or failed to create: %', SQLERRM;
END;
END$$;

-- Create roles (idempotent)
-- ⚠️  SECURITY WARNING: These are TEMPORARY INITIALIZATION PASSWORDS!
-- After container startup, you MUST run ./update-database-credentials.sh
-- to replace these default passwords with secure credentials from .env
--
-- Workflow:
--   1. ./generate-credentials.sh  (creates .env with secure passwords)
--   2. docker-compose up -d        (initializes databases with temp passwords)
--   3. ./update-database-credentials.sh  (updates to secure passwords from .env)
--   4. ./update-kong-config.sh     (updates Kong with API key)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'n8n') THEN
CREATE ROLE n8n LOGIN PASSWORD 'n8n_temp_init_pwd';
END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'exploitdb') THEN
CREATE ROLE exploitdb LOGIN PASSWORD 'exploitdb_temp_init_pwd';
END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'scans') THEN
CREATE ROLE scans LOGIN PASSWORD 'scans_temp_init_pwd';
END IF;
END$$;

-------------------------
-- DATABASE: n8n
-------------------------
-- Create DB (may error if exists)
CREATE DATABASE n8n OWNER n8n TEMPLATE template0 ENCODING 'UTF8';

-- Switch to n8n DB (psql meta-command)
\connect n8n

-- Ensure extensions in this DB
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;
DO $$
BEGIN
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'vector extension not available: %', SQLERRM;
END;
END$$;

-- Ensure schema + privileges
CREATE SCHEMA IF NOT EXISTS n8n AUTHORIZATION n8n;
ALTER ROLE n8n SET search_path TO n8n, public;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO n8n;
GRANT USAGE, CREATE ON SCHEMA public TO n8n;

-- n8n/core tables (idempotent)
CREATE TABLE IF NOT EXISTS public.assets (
                                           id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  ip           INET,
  hostname     TEXT,
  env          TEXT,
  tags         TEXT[] DEFAULT '{}',
  first_seen   TIMESTAMPTZ DEFAULT now(),
  last_seen    TIMESTAMPTZ DEFAULT now()
  );
CREATE INDEX IF NOT EXISTS ix_assets_ip ON public.assets(ip);

CREATE TABLE IF NOT EXISTS public.scans (
                                          id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tool          TEXT,
  profile       TEXT,
  started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at   TIMESTAMPTZ,
  args          TEXT,
  source_path   TEXT,
  metadata      JSONB DEFAULT '{}'::jsonb
  );
CREATE INDEX IF NOT EXISTS scans_started_idx ON public.scans (started_at);

CREATE TABLE IF NOT EXISTS public.ports (
                                          id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  asset_id     UUID REFERENCES public.assets(id) ON DELETE CASCADE,
  proto        TEXT NOT NULL CHECK (proto IN ('tcp','udp')),
  port         INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  service      TEXT,
  product      TEXT,
  version      TEXT,
  banner       TEXT,
  first_seen   TIMESTAMPTZ DEFAULT now(),
  last_seen    TIMESTAMPTZ DEFAULT now(),
  is_open      BOOLEAN NOT NULL DEFAULT TRUE
  );
CREATE UNIQUE INDEX IF NOT EXISTS ux_ports_asset_proto_port ON public.ports (asset_id, proto, port);

-- findings, web_findings, rag_documents
CREATE TABLE IF NOT EXISTS public.findings (
                                             id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  asset_id     UUID REFERENCES public.assets(id) ON DELETE CASCADE,
  port_id      UUID REFERENCES public.ports(id) ON DELETE SET NULL,
  source_tool  TEXT,
  rule_id      TEXT,
  title        TEXT,
  description  TEXT,
  evidence     JSONB DEFAULT '{}'::jsonb,
  cve          TEXT[],
  cvss         NUMERIC,
  severity     TEXT CHECK (severity IN ('info','low','medium','high','critical')),
  observed_at  TIMESTAMPTZ DEFAULT now(),
  status       TEXT CHECK (status IN ('open','accepted','fixed','retest-passed','retest-failed')) DEFAULT 'open',
  confidence   TEXT,
  refs         JSONB DEFAULT '{}'::jsonb,
  tool_finding_id TEXT,
  remediation  JSONB DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ DEFAULT now(),
  updated_at   TIMESTAMPTZ DEFAULT now()
  );
CREATE INDEX IF NOT EXISTS findings_asset_sev_idx ON public.findings (asset_id, severity);
CREATE INDEX IF NOT EXISTS findings_cve_gin ON public.findings USING GIN (cve);
CREATE INDEX IF NOT EXISTS findings_evidence_gin ON public.findings USING GIN ((evidence));

CREATE TABLE IF NOT EXISTS public.web_findings (
                                                 id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  asset_id     UUID REFERENCES public.assets(id) ON DELETE CASCADE,
  url          TEXT NOT NULL,
  source       TEXT NOT NULL,
  issue_type   TEXT,
  name         TEXT,
  severity     TEXT,
  evidence     TEXT,
  status_code  INTEGER,
  first_seen   TIMESTAMPTZ DEFAULT now(),
  last_seen    TIMESTAMPTZ DEFAULT now()
  );

-- RAG documents (embedding column only if vector installed)
DO $$
BEGIN
  IF to_regclass('public.rag_documents') IS NULL THEN
CREATE TABLE public.rag_documents (
                                    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                    asset_id    UUID REFERENCES public.assets(id) ON DELETE SET NULL,
                                    finding_id  UUID REFERENCES public.findings(id) ON DELETE SET NULL,
                                    port_id     UUID REFERENCES public.ports(id) ON DELETE SET NULL,
                                    scan_id     UUID REFERENCES public.scans(id) ON DELETE SET NULL,
                                    title       TEXT,
                                    text_chunk  TEXT NOT NULL,
                                    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
                                    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
END IF;
END$$;

-- try to add an embedding column if vector exists (safe to fail)
DO $$
BEGIN
BEGIN
ALTER TABLE public.rag_documents ADD COLUMN IF NOT EXISTS embedding vector(384);
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'embedding column not created (vector missing?) - %', SQLERRM;
END;
END$$;

-- FTS column and indexes for rag_documents if present
DO $$
BEGIN
  IF to_regclass('public.rag_documents') IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute
      WHERE attrelid = 'public.rag_documents'::regclass AND attname = 'fts'
    ) THEN
ALTER TABLE public.rag_documents
  ADD COLUMN fts tsvector
    GENERATED ALWAYS AS (to_tsvector('english', coalesce(title,'') || ' ' || text_chunk)) STORED;
END IF;
    -- indexes
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'rag_docs_meta_gin') THEN
CREATE INDEX rag_docs_meta_gin ON public.rag_documents USING GIN (metadata);
END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'rag_docs_fts_idx') THEN
CREATE INDEX rag_docs_fts_idx ON public.rag_documents USING GIN (fts);
END IF;
END IF;
END$$;

-- default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON TABLES TO n8n;
GRANT USAGE, CREATE ON SCHEMA public TO n8n;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO n8n;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO n8n;

-------------------------
-- DATABASE: exploitdb
-------------------------
\connect postgres
CREATE DATABASE exploitdb OWNER exploitdb TEMPLATE template0 ENCODING 'UTF8';
\connect exploitdb

-- Ensure extensions in exploitdb
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- edb_exploits table (idempotent)
DO $$
BEGIN
  IF to_regclass('public.edb_exploits') IS NULL THEN
CREATE TABLE public.edb_exploits (
                                   edb_id        INTEGER PRIMARY KEY,
                                   file_path     TEXT NOT NULL,
                                   title         TEXT,
                                   date_published DATE,
                                   author        TEXT,
                                   type          TEXT,
                                   platform      TEXT,
                                   port          TEXT,
                                   cves          TEXT[],
                                   description   TEXT
);
END IF;
END$$;

-- generated FTS column
DO $$
BEGIN
  IF to_regclass('public.edb_exploits') IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM pg_attribute
      WHERE attrelid = 'public.edb_exploits'::regclass AND attname = 'fts'
    ) THEN
ALTER TABLE public.edb_exploits
  ADD COLUMN fts tsvector
    GENERATED ALWAYS AS (
      setweight(to_tsvector('simple', coalesce(title,'')), 'A') ||
      setweight(to_tsvector('simple', coalesce(description,'')), 'B') ||
      to_tsvector('simple', coalesce(platform,'')) ||
      to_tsvector('simple', coalesce(type,''))
      ) STORED;
END IF;

    -- indexes
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_edb_exploits_fts') THEN
CREATE INDEX idx_edb_exploits_fts ON public.edb_exploits USING GIN (fts);
END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_edb_exploits_cves') THEN
CREATE INDEX idx_edb_exploits_cves ON public.edb_exploits USING GIN (cves);
END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'idx_edb_exploits_title_trgm') THEN
CREATE INDEX idx_edb_exploits_title_trgm ON public.edb_exploits USING GIN (title gin_trgm_ops);
END IF;
END IF;
END$$;

-- optional raw file storage
DO $$
BEGIN
  IF to_regclass('public.edb_raw_files') IS NULL THEN
CREATE TABLE public.edb_raw_files (
                                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                                    edb_id INTEGER REFERENCES public.edb_exploits(edb_id) ON DELETE CASCADE,
                                    file_content BYTEA,
                                    created_at TIMESTAMPTZ DEFAULT now()
);
END IF;
END$$;

-- grant exploitdb role privileges
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO exploitdb;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO exploitdb;

-------------------------
-- DATABASE: scans
-------------------------
\connect postgres
CREATE DATABASE scans OWNER scans TEMPLATE template0 ENCODING 'UTF8';
\connect scans

-- extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;
DO $$
BEGIN
BEGIN
    CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'vector extension not available in scans DB: %', SQLERRM;
END;
END$$;

-- core assets / ports / scans / findings (idempotent)
DO $$
BEGIN
  IF to_regclass('public.assets') IS NULL THEN
CREATE TABLE public.assets (
                             id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                             ip         INET UNIQUE NOT NULL,
                             hostname   TEXT,
                             env        TEXT,
                             tags       TEXT[],
                             first_seen TIMESTAMPTZ DEFAULT now(),
                             last_seen  TIMESTAMPTZ DEFAULT now(),
                             os         TEXT
);
ELSE
    -- ensure os column exists
BEGIN
ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS os TEXT;
EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'assets.os add ignored: %', SQLERRM;
END;
END IF;
END$$;
CREATE INDEX IF NOT EXISTS ix_assets_ip ON public.assets(ip);

DO $$
BEGIN
  IF to_regclass('public.scans') IS NULL THEN
CREATE TABLE public.scans (
                            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                            tool text,
                            profile text,
                            started_at timestamptz DEFAULT now(),
                            finished_at timestamptz,
                            args text,
                            metadata jsonb DEFAULT '{}'::jsonb
);
END IF;
END$$;

DO $$
BEGIN
  IF to_regclass('public.ports') IS NULL THEN
CREATE TABLE public.ports (
                            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                            asset_id uuid REFERENCES public.assets(id) ON DELETE CASCADE,
                            proto text NOT NULL,
                            port integer NOT NULL,
                            service text,
                            product text,
                            version text,
                            banner text,
                            first_seen timestamptz DEFAULT now(),
                            last_seen timestamptz DEFAULT now(),
                            is_open boolean DEFAULT true,
                            created_at timestamptz DEFAULT CURRENT_TIMESTAMP
);
ELSE
    -- ensure created_at column exists
BEGIN
ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT CURRENT_TIMESTAMP;
EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'ports.created_at add ignored: %', SQLERRM;
END;
END IF;
END$$;

CREATE UNIQUE INDEX IF NOT EXISTS ux_ports_asset_proto_port_scans ON public.ports(asset_id, proto, port);

DO $$
BEGIN
  IF to_regclass('public.findings') IS NULL THEN
CREATE TABLE public.findings (
                               id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                               title text,
                               severity text,
                               asset_id uuid REFERENCES public.assets(id),
                               port integer,
                               created_at timestamptz DEFAULT now(),
                               updated_at timestamptz DEFAULT now(),
                               details jsonb
);
END IF;
END$$;

-- port_observation (complex; create or alter as needed)
DO $$
BEGIN
  IF to_regclass('public.port_observation') IS NULL THEN
CREATE TABLE public.port_observation (
                                       id           uuid DEFAULT gen_random_uuid() PRIMARY KEY,
                                       scan_id      uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
                                       asset_id     uuid REFERENCES public.assets(id) ON DELETE SET NULL,
                                       ip           inet NOT NULL,
                                       proto        text NOT NULL CHECK (proto IN ('tcp','udp')),
                                       port         integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
                                       state        text,
                                       ttl          integer,
                                       banner       text,
                                       service      jsonb DEFAULT '{}'::jsonb,
                                       tool         text NOT NULL,
                                       raw          jsonb DEFAULT '{}'::jsonb,
                                       observed_at  timestamptz DEFAULT now()
);
ELSE
ALTER TABLE public.port_observation
  ADD COLUMN IF NOT EXISTS service jsonb DEFAULT '{}'::jsonb;
ALTER TABLE public.port_observation
  ADD COLUMN IF NOT EXISTS raw jsonb DEFAULT '{}'::jsonb;
ALTER TABLE public.port_observation
  ADD COLUMN IF NOT EXISTS observed_at timestamptz DEFAULT now();
-- ensure id default
BEGIN
      PERFORM 1 FROM pg_attrdef d
        JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
        WHERE d.adrelid = 'public.port_observation'::regclass AND a.attname='id';
      IF NOT FOUND THEN
ALTER TABLE public.port_observation ALTER COLUMN id SET DEFAULT gen_random_uuid();
END IF;
EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'port_observation id default check failed: %', SQLERRM;
END;
END IF;
END$$;

CREATE INDEX IF NOT EXISTS port_observation_asset_proto_port_idx ON public.port_observation (asset_id, proto, port);
CREATE INDEX IF NOT EXISTS port_observation_ip_proto_port_idx ON public.port_observation (ip, proto, port);
CREATE INDEX IF NOT EXISTS port_obs_raw_gin ON public.port_observation USING GIN (raw);
CREATE INDEX IF NOT EXISTS port_obs_service_gin ON public.port_observation USING GIN (service);

-- raw_output
DO $$
BEGIN
  IF to_regclass('public.raw_output') IS NULL THEN
CREATE TABLE public.raw_output (
                                 id           uuid DEFAULT gen_random_uuid() PRIMARY KEY,
                                 scan_id      uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
                                 tool         text NOT NULL,
                                 content      bytea NOT NULL,
                                 content_type text NOT NULL,
                                 created_at   timestamptz DEFAULT now()
);
ELSE
ALTER TABLE public.raw_output ADD COLUMN IF NOT EXISTS content_type text;
ALTER TABLE public.raw_output ADD COLUMN IF NOT EXISTS content bytea;
ALTER TABLE public.raw_output ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();
BEGIN
      PERFORM 1 FROM pg_attrdef d
        JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum
        WHERE d.adrelid = 'public.raw_output'::regclass AND a.attname='id';
      IF NOT FOUND THEN
ALTER TABLE public.raw_output ALTER COLUMN id SET DEFAULT gen_random_uuid();
END IF;
EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'raw_output id default check failed: %', SQLERRM;
END;
END IF;
END$$;

-- scan_targets
DO $$
BEGIN
  IF to_regclass('public.scan_targets') IS NULL THEN
CREATE TABLE public.scan_targets (
                                   id       uuid DEFAULT gen_random_uuid() PRIMARY KEY,
                                   scan_id  uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
                                   target   text NOT NULL,
                                   asset_id uuid REFERENCES public.assets(id) ON DELETE SET NULL,
                                   note     text
);
ELSE
ALTER TABLE public.scan_targets ADD COLUMN IF NOT EXISTS note text;
END IF;
END$$;
CREATE INDEX IF NOT EXISTS scan_targets_scan_id_idx ON public.scan_targets (scan_id);

-- finding_evidence
DO $$
BEGIN
  IF to_regclass('public.finding_evidence') IS NULL THEN
CREATE TABLE public.finding_evidence (
                                       id                  uuid DEFAULT gen_random_uuid() PRIMARY KEY,
                                       finding_id          uuid NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
                                       scan_id             uuid REFERENCES public.scans(id) ON DELETE SET NULL,
                                       port_observation_id uuid REFERENCES public.port_observation(id) ON DELETE SET NULL,
                                       snippet             text,
                                       blob                bytea,
                                       metadata            jsonb DEFAULT '{}'::jsonb,
                                       created_at          timestamptz DEFAULT now()
);
ELSE
ALTER TABLE public.finding_evidence ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}'::jsonb;
END IF;
END$$;
CREATE INDEX IF NOT EXISTS finding_evidence_meta_gin ON public.finding_evidence USING GIN (metadata);

-- cve cache
DO $$
BEGIN
  IF to_regclass('public.cve') IS NULL THEN
CREATE TABLE public.cve (
                          id            text PRIMARY KEY,
                          summary       text,
                          cvss          numeric,
                          published     timestamptz,
                          last_modified timestamptz,
                          refs          jsonb DEFAULT '{}'::jsonb
);
END IF;
END$$;

-- touch updated_at trigger and attach to public.findings
CREATE OR REPLACE FUNCTION public._touch_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF to_regclass('public.findings') IS NOT NULL THEN
    PERFORM 1;
BEGIN
DROP TRIGGER IF EXISTS trg_findings_touch_updated ON public.findings;
EXCEPTION WHEN OTHERS THEN
      NULL;
END;
CREATE TRIGGER trg_findings_touch_updated
  BEFORE UPDATE ON public.findings
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF;
END$$;

-- JOBS / TASKS (place in scans DB)
-- Ensure extensions that jobs rely on
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF to_regclass('public.jobs') IS NULL THEN
CREATE TABLE public.jobs (
                           id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                           type             text NOT NULL CHECK (type IN ('masscan-nmap')),
                           status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','finished','failed','canceled')),
                           params           jsonb NOT NULL DEFAULT '{}'::jsonb,
                           total_tasks      integer NOT NULL DEFAULT 0,
                           finished_tasks   integer NOT NULL DEFAULT 0,
                           error            text,
                           idempotency_key  text UNIQUE,
                           created_at       timestamptz NOT NULL DEFAULT now(),
                           started_at       timestamptz,
                           finished_at      timestamptz
);
CREATE INDEX idx_jobs_status ON public.jobs(status);
CREATE INDEX idx_jobs_created_at ON public.jobs(created_at DESC);
END IF;
END$$;

DO $$
BEGIN
  IF to_regclass('public.tasks') IS NULL THEN
CREATE TABLE public.tasks (
                            id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                            job_id       uuid NOT NULL REFERENCES public.jobs(id) ON DELETE CASCADE,
                            type         text NOT NULL CHECK (type IN ('pipeline','masscan','nmap','followup')),
                            target_host  inet,
                            target_port  integer,
                            proto        text,
                            status       text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','finished','failed','canceled')),
                            attempt      integer NOT NULL DEFAULT 0,
                            last_error   text,
                            created_at   timestamptz NOT NULL DEFAULT now(),
                            started_at   timestamptz,
                            finished_at  timestamptz
);
-- Uniqueness for target tasks within a job
CREATE UNIQUE INDEX ux_tasks_job_target ON public.tasks (job_id, type, target_host, target_port, COALESCE(proto,''));
CREATE INDEX idx_tasks_job ON public.tasks(job_id);
CREATE INDEX idx_tasks_status ON public.tasks(status);
CREATE INDEX idx_tasks_job_status ON public.tasks(job_id, status);
END IF;
END$$;

-- ===============================
-- web_findings table (CRITICAL - used by web_scanner.py)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.web_findings') IS NULL THEN
    CREATE TABLE public.web_findings (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id     uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      url          text NOT NULL,
      source       text NOT NULL,  -- 'gobuster', 'zap', 'playwright'
      issue_type   text,
      name         text,
      severity     text CHECK (severity IN ('info','low','medium','high','critical') OR severity IS NULL),
      evidence     text,
      status_code  integer,
      method       text,  -- HTTP method (GET, POST, etc.)
      payload      text,  -- For ZAP - attack payload used
      description  text,  -- Finding description from scanner
      solution     text,  -- Recommended remediation
      reference    text,  -- External reference links
      confidence   text,  -- Scanner confidence level
      tags         jsonb, -- Additional categorization tags
      cwe          text[],  -- Common Weakness Enumeration IDs
      refs         jsonb DEFAULT '{}'::jsonb,  -- External references/links (renamed from 'references' - reserved keyword)
      first_seen   timestamptz NOT NULL DEFAULT now(),
      last_seen    timestamptz NOT NULL DEFAULT now(),
      created_at   timestamptz NOT NULL DEFAULT now(),
      updated_at   timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_web_findings_asset_id ON public.web_findings(asset_id);
    CREATE INDEX idx_web_findings_url ON public.web_findings(url);
    CREATE INDEX idx_web_findings_source ON public.web_findings(source);
    CREATE INDEX idx_web_findings_severity ON public.web_findings(severity);
    CREATE INDEX idx_web_findings_created_at ON public.web_findings(created_at DESC);
  ELSE
    -- Ensure all columns exist if table was created by older version
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS method text;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS payload text;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS description text;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS solution text;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS reference text;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS confidence text;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS tags jsonb;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS cwe text[];
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS refs jsonb DEFAULT '{}'::jsonb;
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();
    ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT now();
  END IF;
END$$;

-- ===============================
-- vulns table (CRITICAL - used by api.py /vulns endpoint)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.vulns') IS NULL THEN
    CREATE TABLE public.vulns (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id     uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      port_id      uuid REFERENCES public.ports(id) ON DELETE CASCADE,
      script       text NOT NULL,  -- NSE script name that found the vuln
      output       text NOT NULL,  -- Full output from the script
      severity     text CHECK (severity IN ('info','low','medium','high','critical')),
      cve          text[],  -- CVE identifiers if applicable
      cvss         numeric,  -- CVSS score
      refs         jsonb DEFAULT '{}'::jsonb,  -- Links to advisories, etc. (renamed from 'references' - reserved keyword)
      metadata     jsonb DEFAULT '{}'::jsonb,  -- Additional structured data
      created_at   timestamptz NOT NULL DEFAULT now(),
      updated_at   timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_vulns_asset_id ON public.vulns(asset_id);
    CREATE INDEX idx_vulns_port_id ON public.vulns(port_id);
    CREATE INDEX idx_vulns_script ON public.vulns(script);
    CREATE INDEX idx_vulns_severity ON public.vulns(severity);
    CREATE INDEX idx_vulns_cve_gin ON public.vulns USING GIN (cve);
    CREATE INDEX idx_vulns_created_at ON public.vulns(created_at DESC);
  END IF;
END$$;

-- ===============================
-- scan_recommendations table (used by scan_recommender.py)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.scan_recommendations') IS NULL THEN
    CREATE TABLE public.scan_recommendations (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id     uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      ip           inet,  -- Denormalized for quick filtering
      service      text,
      banner       text,
      scanner      text NOT NULL,  -- 'nmap', 'nuclei', 'zap', 'playwright'
      action       text,  -- Tool-specific action
      script       text,  -- For nmap scripts
      template     text,  -- For nuclei templates
      source       text NOT NULL DEFAULT 'rules',  -- 'rules', 'ollama', 'autogen'
      model        text,  -- LLM model used if source='ollama'
      extra        jsonb DEFAULT '{}'::jsonb,  -- Additional metadata
      confidence   numeric,  -- 0.0-1.0 confidence score
      priority     integer DEFAULT 50,  -- 0-100 priority for execution order
      status       text DEFAULT 'pending' CHECK (status IN ('pending','queued','running','completed','failed','skipped')),
      executed_at  timestamptz,
      created_at   timestamptz NOT NULL DEFAULT now(),
      updated_at   timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_scan_recommendations_asset_id ON public.scan_recommendations(asset_id);
    CREATE INDEX idx_scan_recommendations_ip ON public.scan_recommendations(ip);
    CREATE INDEX idx_scan_recommendations_scanner ON public.scan_recommendations(scanner);
    CREATE INDEX idx_scan_recommendations_status ON public.scan_recommendations(status);
    CREATE INDEX idx_scan_recommendations_priority ON public.scan_recommendations(priority DESC);
    CREATE INDEX idx_scan_recommendations_created_at ON public.scan_recommendations(created_at DESC);
  END IF;
END$$;

-- Add fingerprint column for deduplication
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = 'public.scan_recommendations'::regclass AND attname = 'fingerprint'
  ) THEN
    ALTER TABLE public.scan_recommendations
      ADD COLUMN fingerprint text
      GENERATED ALWAYS AS (
        md5(COALESCE(ip::text, '') || '|' ||
            COALESCE(service, '') || '|' ||
            COALESCE(scanner, '') || '|' ||
            COALESCE(action, '') || '|' ||
            COALESCE(script, '') || '|' ||
            COALESCE(template, ''))
      ) STORED;
    CREATE UNIQUE INDEX ux_scan_recommendations_fingerprint
      ON public.scan_recommendations(fingerprint);
  END IF;
END$$;

-- ===============================
-- playwright_scans table (for Phase 2)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.playwright_scans') IS NULL THEN
    CREATE TABLE public.playwright_scans (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id     uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      url          text NOT NULL,
      status       text NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued','running','completed','failed')),
      start_time   timestamptz,
      end_time     timestamptz,
      browser      text DEFAULT 'chromium',  -- 'chromium', 'firefox', 'webkit'
      viewport     jsonb,  -- {width, height}
      user_agent   text,
      cookies      jsonb DEFAULT '[]'::jsonb,  -- Initial cookies to set
      screenshots  integer DEFAULT 0,  -- Count of screenshots taken
      dom_snapshot boolean DEFAULT false,  -- Whether DOM was captured
      console_logs jsonb DEFAULT '[]'::jsonb,  -- Browser console output
      network_logs jsonb DEFAULT '[]'::jsonb,  -- Network requests
      errors       jsonb DEFAULT '[]'::jsonb,  -- JavaScript errors encountered
      metadata     jsonb DEFAULT '{}'::jsonb,
      created_at   timestamptz NOT NULL DEFAULT now(),
      updated_at   timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_playwright_scans_asset_id ON public.playwright_scans(asset_id);
    CREATE INDEX idx_playwright_scans_url ON public.playwright_scans(url);
    CREATE INDEX idx_playwright_scans_status ON public.playwright_scans(status);
    CREATE INDEX idx_playwright_scans_created_at ON public.playwright_scans(created_at DESC);
  END IF;
END$$;

-- ===============================
-- playwright_findings table (for Phase 2)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.playwright_findings') IS NULL THEN
    CREATE TABLE public.playwright_findings (
      id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      scan_id           uuid NOT NULL REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
      asset_id          uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      url               text NOT NULL,
      finding_type      text NOT NULL,  -- 'xss', 'csrf', 'clickjacking', 'mixed-content', etc.
      severity          text CHECK (severity IN ('info','low','medium','high','critical')),
      title             text NOT NULL,
      description       text,
      evidence          text,  -- Code snippet, selector, etc.
      location          text,  -- CSS selector or URL fragment
      remediation       text,
      cwe               text[],
      owasp_category    text,  -- 'A01:2021-Broken Access Control', etc.
      refs              jsonb DEFAULT '[]'::jsonb,
      screenshot_id     uuid,  -- Reference to screenshot if applicable
      dom_element       jsonb,  -- Captured DOM node details
      related_request   jsonb,  -- HTTP request that triggered this
      confidence        numeric,  -- 0.0-1.0
      false_positive    boolean DEFAULT false,
      verified          boolean DEFAULT false,
      notes             text,
      created_at        timestamptz NOT NULL DEFAULT now(),
      updated_at        timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_playwright_findings_scan_id ON public.playwright_findings(scan_id);
    CREATE INDEX idx_playwright_findings_asset_id ON public.playwright_findings(asset_id);
    CREATE INDEX idx_playwright_findings_url ON public.playwright_findings(url);
    CREATE INDEX idx_playwright_findings_type ON public.playwright_findings(finding_type);
    CREATE INDEX idx_playwright_findings_severity ON public.playwright_findings(severity);
    CREATE INDEX idx_playwright_findings_cwe_gin ON public.playwright_findings USING GIN (cwe);
    CREATE INDEX idx_playwright_findings_created_at ON public.playwright_findings(created_at DESC);
  END IF;
END$$;

-- ===============================
-- playwright_screenshots table (for Phase 2)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.playwright_screenshots') IS NULL THEN
    CREATE TABLE public.playwright_screenshots (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      scan_id      uuid NOT NULL REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
      url          text NOT NULL,
      viewport     jsonb,  -- {width, height}
      format       text DEFAULT 'png' CHECK (format IN ('png','jpeg','webp')),
      image_data   bytea,  -- Actual screenshot binary
      image_hash   text,  -- SHA256 of image for deduplication
      file_size    integer,
      full_page    boolean DEFAULT false,
      selector     text,  -- If screenshot is of specific element
      metadata     jsonb DEFAULT '{}'::jsonb,
      created_at   timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_playwright_screenshots_scan_id ON public.playwright_screenshots(scan_id);
    CREATE INDEX idx_playwright_screenshots_url ON public.playwright_screenshots(url);
    CREATE INDEX idx_playwright_screenshots_hash ON public.playwright_screenshots(image_hash);
    CREATE INDEX idx_playwright_screenshots_created_at ON public.playwright_screenshots(created_at DESC);
  END IF;
END$$;

-- ===============================
-- dom_analysis table (for Phase 2 - client-side security analysis)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.dom_analysis') IS NULL THEN
    CREATE TABLE public.dom_analysis (
      id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      scan_id           uuid NOT NULL REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
      asset_id          uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      url               text NOT NULL,
      forms_count       integer DEFAULT 0,
      forms             jsonb DEFAULT '[]'::jsonb,  -- Form details
      inputs_count      integer DEFAULT 0,
      cookies           jsonb DEFAULT '[]'::jsonb,
      local_storage     jsonb DEFAULT '{}'::jsonb,
      session_storage   jsonb DEFAULT '{}'::jsonb,
      javascript_libs   jsonb DEFAULT '[]'::jsonb,  -- Detected JS frameworks/libs
      csp_header        text,  -- Content Security Policy
      cors_enabled      boolean,
      cors_config       jsonb DEFAULT '{}'::jsonb,
      security_headers  jsonb DEFAULT '{}'::jsonb,  -- All security-related headers
      external_scripts  jsonb DEFAULT '[]'::jsonb,  -- External JS sources
      mixed_content     boolean DEFAULT false,  -- HTTP resources on HTTPS page
      websockets        jsonb DEFAULT '[]'::jsonb,
      postmessage_usage boolean DEFAULT false,
      dom_snapshot      text,  -- Full HTML snapshot
      metadata          jsonb DEFAULT '{}'::jsonb,
      created_at        timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_dom_analysis_scan_id ON public.dom_analysis(scan_id);
    CREATE INDEX idx_dom_analysis_asset_id ON public.dom_analysis(asset_id);
    CREATE INDEX idx_dom_analysis_url ON public.dom_analysis(url);
    CREATE INDEX idx_dom_analysis_created_at ON public.dom_analysis(created_at DESC);
  END IF;
END$$;

-- ===============================
-- zap_sessions table (to link ZAP scans with other scans)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.zap_sessions') IS NULL THEN
    CREATE TABLE public.zap_sessions (
      id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      playwright_scan_id uuid REFERENCES public.playwright_scans(id) ON DELETE SET NULL,
      web_scan_job_id   uuid,  -- Reference to web scanner job
      session_name      text NOT NULL,
      zap_api_key       text,
      context_name      text,
      sites             jsonb DEFAULT '[]'::jsonb,  -- List of sites in session
      spider_completed  boolean DEFAULT false,
      ascan_completed   boolean DEFAULT false,
      alerts_count      integer DEFAULT 0,
      session_file      text,  -- ZAP session file path
      created_at        timestamptz NOT NULL DEFAULT now(),
      updated_at        timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_zap_sessions_playwright_scan_id ON public.zap_sessions(playwright_scan_id);
    CREATE INDEX idx_zap_sessions_created_at ON public.zap_sessions(created_at DESC);
  END IF;
END$$;

-- ===============================
-- Triggers for updated_at columns on new tables
-- ===============================

-- web_findings trigger
DO $$
BEGIN
  IF to_regclass('public.web_findings') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_web_findings_updated_at ON public.web_findings;
    CREATE TRIGGER trg_web_findings_updated_at
      BEFORE UPDATE ON public.web_findings
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- vulns trigger
DO $$
BEGIN
  IF to_regclass('public.vulns') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_vulns_updated_at ON public.vulns;
    CREATE TRIGGER trg_vulns_updated_at
      BEFORE UPDATE ON public.vulns
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- scan_recommendations trigger
DO $$
BEGIN
  IF to_regclass('public.scan_recommendations') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_scan_recommendations_updated_at ON public.scan_recommendations;
    CREATE TRIGGER trg_scan_recommendations_updated_at
      BEFORE UPDATE ON public.scan_recommendations
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- playwright_scans trigger
DO $$
BEGIN
  IF to_regclass('public.playwright_scans') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_playwright_scans_updated_at ON public.playwright_scans;
    CREATE TRIGGER trg_playwright_scans_updated_at
      BEFORE UPDATE ON public.playwright_scans
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- playwright_findings trigger
DO $$
BEGIN
  IF to_regclass('public.playwright_findings') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_playwright_findings_updated_at ON public.playwright_findings;
    CREATE TRIGGER trg_playwright_findings_updated_at
      BEFORE UPDATE ON public.playwright_findings
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- zap_sessions trigger
DO $$
BEGIN
  IF to_regclass('public.zap_sessions') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_zap_sessions_updated_at ON public.zap_sessions;
    CREATE TRIGGER trg_zap_sessions_updated_at
      BEFORE UPDATE ON public.zap_sessions
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- ===============================
-- credential_findings table (for Brutus credential testing results)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.credential_findings') IS NULL THEN
    CREATE TABLE public.credential_findings (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id      uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      port_id       uuid REFERENCES public.ports(id) ON DELETE SET NULL,
      ip            inet NOT NULL,
      port          integer NOT NULL,
      protocol      text NOT NULL,           -- ssh, ftp, mysql, smb, etc.
      username      text NOT NULL,
      valid_cred    boolean NOT NULL DEFAULT true,
      auth_type     text DEFAULT 'password', -- password, key, badkey
      severity      text DEFAULT 'critical',
      banner        text,
      duration_ms   numeric,
      source        text DEFAULT 'brutus',
      metadata      jsonb DEFAULT '{}'::jsonb,
      created_at    timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_credential_findings_asset_id ON public.credential_findings(asset_id);
    CREATE INDEX idx_credential_findings_ip ON public.credential_findings(ip);
    CREATE INDEX idx_credential_findings_protocol ON public.credential_findings(protocol);
    CREATE INDEX idx_credential_findings_created_at ON public.credential_findings(created_at DESC);
  END IF;
END$$;

-- ===============================
-- recon_findings table (for dnsx, tlsx, asnmap, uncover, cloudlist)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.recon_findings') IS NULL THEN
    CREATE TABLE public.recon_findings (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id      uuid REFERENCES public.assets(id) ON DELETE SET NULL,
      source        text NOT NULL,            -- dnsx, tlsx, asnmap, uncover, cloudlist
      finding_type  text NOT NULL,            -- dns_record, tls_cert, asn_mapping, etc.
      target        text NOT NULL,            -- domain, IP, ASN queried
      data          jsonb NOT NULL,           -- tool-specific structured output
      severity      text CHECK (severity IN ('info','low','medium','high','critical','error','recon')),
      created_at    timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_recon_findings_source ON public.recon_findings(source);
    CREATE INDEX idx_recon_findings_finding_type ON public.recon_findings(finding_type);
    CREATE INDEX idx_recon_findings_target ON public.recon_findings(target);
    CREATE INDEX idx_recon_findings_asset_id ON public.recon_findings(asset_id);
    CREATE INDEX idx_recon_findings_created_at ON public.recon_findings(created_at DESC);
  END IF;
END$$;

-- Widen recon_findings severity constraint if table already exists (add 'error','recon')
DO $$
BEGIN
  ALTER TABLE public.recon_findings DROP CONSTRAINT IF EXISTS recon_findings_severity_check;
  ALTER TABLE public.recon_findings ADD CONSTRAINT recon_findings_severity_check
    CHECK (severity IN ('info','low','medium','high','critical','error','recon'));
EXCEPTION WHEN OTHERS THEN NULL;
END$$;

-- Widen web_findings severity constraint if table already exists (add 'error','recon')
DO $$
BEGIN
  ALTER TABLE public.web_findings DROP CONSTRAINT IF EXISTS web_findings_severity_check;
  ALTER TABLE public.web_findings ADD CONSTRAINT web_findings_severity_check
    CHECK (severity IN ('info','low','medium','high','critical','error','recon') OR severity IS NULL);
EXCEPTION WHEN OTHERS THEN NULL;
END$$;

-- Backfill existing httpx recon_findings: NULL/info → error or recon
UPDATE public.recon_findings
SET severity = 'recon'
WHERE source = 'httpx' AND severity = 'info';

UPDATE public.recon_findings
SET severity = 'error'
WHERE source = 'httpx' AND severity IS NULL;

-- Backfill existing httpx web_findings: set error/recon severity
UPDATE public.web_findings
SET severity = 'error'
WHERE source = 'httpx' AND (severity IS NULL AND evidence IS NULL);

UPDATE public.web_findings
SET severity = 'recon'
WHERE source = 'httpx' AND severity IS NULL AND evidence IS NOT NULL;

-- housekeeping grants for scans DB
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scans;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scans;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO scans;

-------------------------
-- Final notes / helper views
-------------------------
\connect n8n
-- recent high severity rag docs view (if rag_documents present)
DO $$
BEGIN
  IF to_regclass('public.rag_documents') IS NOT NULL THEN
    CREATE OR REPLACE VIEW public.rag_recent_high AS
SELECT title, text_chunk, metadata, created_at
FROM public.rag_documents
WHERE (metadata->>'severity') IN ('high','critical')
  AND created_at >= now() - interval '30 days';
END IF;
END$$;

\connect scans
-- helpful indexes that may be missing (safety)
CREATE INDEX IF NOT EXISTS idx_scan_targets_target ON public.scan_targets(target);

-- ===============================
-- Helpful views for scans database
-- ===============================

-- View: Recent high-severity findings across all sources
CREATE OR REPLACE VIEW public.all_high_severity_findings AS
SELECT
    'web' as source,
    id,
    asset_id,
    url as location,
    name as title,
    severity,
    evidence,
    created_at
FROM public.web_findings
WHERE severity IN ('high', 'critical')
UNION ALL
SELECT
    'vuln' as source,
    v.id,
    v.asset_id,
    host(a.ip)::text || ':' || p.port as location,
    v.script as title,
    v.severity,
    v.output as evidence,
    v.created_at
FROM public.vulns v
JOIN public.ports p ON v.port_id = p.id
JOIN public.assets a ON v.asset_id = a.id
WHERE v.severity IN ('high', 'critical')
UNION ALL
SELECT
    'playwright' as source,
    pf.id,
    pf.asset_id,
    pf.url as location,
    pf.title,
    pf.severity,
    pf.evidence,
    pf.created_at
FROM public.playwright_findings pf
WHERE pf.severity IN ('high', 'critical')
ORDER BY created_at DESC;

-- View: Scan recommendations pending execution
CREATE OR REPLACE VIEW public.pending_scan_recommendations AS
SELECT
    sr.id,
    sr.ip,
    sr.service,
    sr.scanner,
    sr.action,
    sr.script,
    sr.template,
    sr.priority,
    sr.confidence,
    sr.created_at,
    a.hostname
FROM public.scan_recommendations sr
LEFT JOIN public.assets a ON sr.asset_id = a.id
WHERE sr.status = 'pending'
ORDER BY sr.priority DESC, sr.created_at ASC;

-- ===============================
-- agent_sessions table (for Phase 3 - Autogen multi-agent system)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.agent_sessions') IS NULL THEN
    CREATE TABLE public.agent_sessions (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      session_name        text NOT NULL,
      target_description  text NOT NULL,
      status              text NOT NULL DEFAULT 'active'
                          CHECK (status IN ('active','completed','failed','stopped','stalled')),
      configuration       jsonb DEFAULT '{}'::jsonb,  -- Agent configuration
      summary             text,  -- Final summary of the session
      metadata            jsonb DEFAULT '{}'::jsonb,  -- Additional metadata
      created_at          timestamptz NOT NULL DEFAULT now(),
      updated_at          timestamptz NOT NULL DEFAULT now(),
      end_time            timestamptz
    );
    CREATE INDEX idx_agent_sessions_status ON public.agent_sessions(status);
    CREATE INDEX idx_agent_sessions_created_at ON public.agent_sessions(created_at DESC);
  END IF;
END$$;

-- ===============================
-- agent_messages table (for Phase 3 - stores agent conversation)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.agent_messages') IS NULL THEN
    CREATE TABLE public.agent_messages (
      id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id  uuid NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
      agent_name  text NOT NULL,  -- Name of the agent (Coordinator, Scanner, Analyzer, etc.)
      role        text NOT NULL,  -- 'system', 'user', 'assistant', 'function'
      content     text NOT NULL,  -- Message content
      metadata    jsonb DEFAULT '{}'::jsonb,  -- Function calls, tool results, etc.
      created_at  timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_agent_messages_session_id ON public.agent_messages(session_id);
    CREATE INDEX idx_agent_messages_agent_name ON public.agent_messages(agent_name);
    CREATE INDEX idx_agent_messages_created_at ON public.agent_messages(created_at DESC);
  END IF;
END$$;

-- agent_sessions trigger
DO $$
BEGIN
  IF to_regclass('public.agent_sessions') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_agent_sessions_updated_at ON public.agent_sessions;
    CREATE TRIGGER trg_agent_sessions_updated_at
      BEFORE UPDATE ON public.agent_sessions
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- ===============================
-- pending_exploits table (for exploit approval workflow)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.pending_exploits') IS NULL THEN
    CREATE TABLE public.pending_exploits (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      asset_id            uuid REFERENCES public.assets(id) ON DELETE CASCADE,
      port_id             uuid REFERENCES public.ports(id) ON DELETE SET NULL,

      -- Exploit source info
      source              text NOT NULL CHECK (source IN ('exploitdb', 'metasploit')),
      exploit_id          text NOT NULL,  -- EDB-ID or MSF module path
      exploit_title       text NOT NULL,
      exploit_type        text CHECK (exploit_type IN ('rce', 'auth_bypass', 'info_disclosure', 'other')),

      -- Target info
      target_ip           inet NOT NULL,
      target_port         integer,
      target_service      text,
      target_version      text,

      -- Customized payload
      customized_command  text NOT NULL,  -- Ready-to-run command/script
      parameters          jsonb DEFAULT '{}'::jsonb,  -- RHOST, RPORT, LHOST, LPORT, etc.
      match_confidence    numeric,  -- 0.0-1.0
      match_reasoning     text,

      -- Approval workflow
      status              text NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed')),
      requested_by        text,  -- Agent or session that requested
      reviewed_by         text,  -- Human approver ID
      reviewed_at         timestamptz,
      rejection_reason    text,

      -- Metadata
      session_id          uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
      metadata            jsonb DEFAULT '{}'::jsonb,
      created_at          timestamptz NOT NULL DEFAULT now(),
      updated_at          timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_pending_exploits_status ON public.pending_exploits(status);
    CREATE INDEX idx_pending_exploits_asset_id ON public.pending_exploits(asset_id);
    CREATE INDEX idx_pending_exploits_session_id ON public.pending_exploits(session_id);
    CREATE INDEX idx_pending_exploits_created_at ON public.pending_exploits(created_at DESC);
  END IF;
END$$;

-- ===============================
-- exploit_results table (stores execution results)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.exploit_results') IS NULL THEN
    CREATE TABLE public.exploit_results (
      id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      pending_exploit_id    uuid NOT NULL REFERENCES public.pending_exploits(id) ON DELETE CASCADE,

      -- Execution info
      executed_at           timestamptz NOT NULL DEFAULT now(),
      completed_at          timestamptz,
      execution_time_ms     integer,

      -- Result
      success               boolean NOT NULL DEFAULT false,
      output                text,  -- Full stdout/stderr
      parsed_result         jsonb DEFAULT '{}'::jsonb,  -- Structured result data

      -- Session info (if shell obtained)
      session_type          text,  -- meterpreter, shell, none
      session_id            text,  -- MSF session ID if created

      -- Evidence
      artifacts             jsonb DEFAULT '[]'::jsonb,

      -- Audit trail
      executor_container    text,  -- Container ID that ran the exploit
      audit_log             jsonb DEFAULT '[]'::jsonb,

      created_at            timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_exploit_results_pending_id ON public.exploit_results(pending_exploit_id);
    CREATE INDEX idx_exploit_results_success ON public.exploit_results(success);
    CREATE INDEX idx_exploit_results_executed_at ON public.exploit_results(executed_at DESC);
  END IF;
END$$;

-- ===============================
-- msf_modules table (Metasploit module cache)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.msf_modules') IS NULL THEN
    CREATE TABLE public.msf_modules (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      module_path         text UNIQUE NOT NULL,  -- exploit/linux/samba/usermap_script
      module_type         text NOT NULL CHECK (module_type IN ('exploit', 'auxiliary', 'post', 'payload', 'encoder', 'nop')),
      name                text NOT NULL,
      description         text,
      rank                text,  -- excellent, great, good, normal, average, low, manual

      -- Targeting
      platforms           text[],  -- linux, windows, unix, osx, multi
      architectures       text[],  -- x86, x64, cmd, php, ruby, python
      targets             jsonb DEFAULT '[]'::jsonb,

      -- References
      cve                 text[],
      edb_id              text[],

      -- Options
      required_options    jsonb DEFAULT '{}'::jsonb,
      optional_options    jsonb DEFAULT '{}'::jsonb,

      -- Metadata
      author              text[],
      disclosure_date     date,
      last_updated        timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_msf_modules_type ON public.msf_modules(module_type);
    CREATE INDEX idx_msf_modules_cve_gin ON public.msf_modules USING GIN (cve);
    CREATE INDEX idx_msf_modules_platforms_gin ON public.msf_modules USING GIN (platforms);
    CREATE INDEX idx_msf_modules_name_trgm ON public.msf_modules USING GIN (name gin_trgm_ops);
  END IF;
END$$;

-- pending_exploits trigger
DO $$
BEGIN
  IF to_regclass('public.pending_exploits') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_pending_exploits_updated_at ON public.pending_exploits;
    CREATE TRIGGER trg_pending_exploits_updated_at
      BEFORE UPDATE ON public.pending_exploits
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- ===============================
-- webhooks table (for webhook notification system)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.webhooks') IS NULL THEN
    CREATE TABLE public.webhooks (
      id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name              text NOT NULL,
      url               text NOT NULL,
      secret            text,  -- HMAC signing key
      enabled           boolean DEFAULT true,
      event_types       text[] DEFAULT ARRAY['scan_completed', 'finding_high'],
      sources           text[],  -- Filter: 'nmap', 'nuclei', 'zap', etc.
      severities        text[],  -- Filter: 'critical', 'high', etc.
      max_retries       integer DEFAULT 3,
      timeout_ms        integer DEFAULT 5000,
      created_at        timestamptz NOT NULL DEFAULT now(),
      updated_at        timestamptz NOT NULL DEFAULT now(),
      last_success      timestamptz,
      failure_count     integer DEFAULT 0
    );
    CREATE INDEX idx_webhooks_enabled ON public.webhooks(enabled);
    CREATE INDEX idx_webhooks_created_at ON public.webhooks(created_at DESC);
  END IF;
END$$;

-- ===============================
-- webhook_events table (delivery tracking)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.webhook_events') IS NULL THEN
    CREATE TABLE public.webhook_events (
      id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      webhook_id        uuid NOT NULL REFERENCES public.webhooks(id) ON DELETE CASCADE,
      event_type        text NOT NULL,
      payload           jsonb NOT NULL,
      status            text DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed', 'retrying')),
      attempt           integer DEFAULT 0,
      response_code     integer,
      error_message     text,
      created_at        timestamptz NOT NULL DEFAULT now(),
      delivered_at      timestamptz,
      next_retry        timestamptz
    );
    CREATE INDEX idx_webhook_events_webhook_id ON public.webhook_events(webhook_id);
    CREATE INDEX idx_webhook_events_status ON public.webhook_events(status);
    CREATE INDEX idx_webhook_events_next_retry ON public.webhook_events(next_retry) WHERE status = 'retrying';
    CREATE INDEX idx_webhook_events_created_at ON public.webhook_events(created_at DESC);
  END IF;
END$$;

-- webhooks trigger for updated_at
DO $$
BEGIN
  IF to_regclass('public.webhooks') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_webhooks_updated_at ON public.webhooks;
    CREATE TRIGGER trg_webhooks_updated_at
      BEFORE UPDATE ON public.webhooks
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- ===============================
-- session_scan_metrics table (persists SessionScanTracker data)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.session_scan_metrics') IS NULL THEN
    CREATE TABLE public.session_scan_metrics (
      id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id        uuid NOT NULL,
      scan_type         text NOT NULL,
      scan_phase        text,
      job_id            text,
      status            text NOT NULL DEFAULT 'running',
      started_at        timestamptz,
      completed_at      timestamptz,
      duration_seconds  numeric,
      params            jsonb DEFAULT '{}'::jsonb,
      result_summary    jsonb DEFAULT '{}'::jsonb,
      created_at        timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_session_scan_metrics_session_id ON public.session_scan_metrics(session_id);
    CREATE INDEX idx_session_scan_metrics_scan_type ON public.session_scan_metrics(scan_type);
    CREATE INDEX idx_session_scan_metrics_created_at ON public.session_scan_metrics(created_at DESC);
  END IF;
END$$;

-- ===============================
-- llm_request_metrics table (per-LLM-call instrumentation for A/B testing)
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.llm_request_metrics') IS NULL THEN
    CREATE TABLE public.llm_request_metrics (
      id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      session_id          uuid NOT NULL,
      agent_name          text,
      model_name          text NOT NULL,
      prompt_tokens       integer,
      completion_tokens   integer,
      total_tokens        integer,
      latency_ms          numeric NOT NULL,
      has_tool_calls      boolean NOT NULL DEFAULT false,
      tool_call_count     integer DEFAULT 0,
      tool_names          text[],
      is_error            boolean NOT NULL DEFAULT false,
      error_message       text,
      request_params      jsonb DEFAULT '{}'::jsonb,
      created_at          timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX idx_llm_request_metrics_session_id ON public.llm_request_metrics(session_id);
    CREATE INDEX idx_llm_request_metrics_model_name ON public.llm_request_metrics(model_name);
    CREATE INDEX idx_llm_request_metrics_agent_name ON public.llm_request_metrics(agent_name);
    CREATE INDEX idx_llm_request_metrics_created_at ON public.llm_request_metrics(created_at DESC);
  END IF;
END$$;

-- llm_model_comparison convenience VIEW
CREATE OR REPLACE VIEW public.llm_model_comparison AS
SELECT
    model_name,
    COUNT(*) AS total_requests,
    ROUND(AVG(latency_ms)::numeric, 1) AS avg_latency_ms,
    ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p50_latency_ms,
    ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p95_latency_ms,
    ROUND(AVG(total_tokens)::numeric, 0) AS avg_total_tokens,
    ROUND(AVG(prompt_tokens)::numeric, 0) AS avg_prompt_tokens,
    ROUND(AVG(completion_tokens)::numeric, 0) AS avg_completion_tokens,
    ROUND(SUM(CASE WHEN has_tool_calls THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(*), 0) * 100, 1) AS tool_call_rate_pct,
    ROUND(SUM(CASE WHEN is_error THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(*), 0) * 100, 1) AS error_rate_pct,
    COUNT(DISTINCT session_id) AS session_count
FROM public.llm_request_metrics
GROUP BY model_name;

-- ===============================
-- pipeline_performance VIEW (unions timing data from existing tables)
-- ===============================
CREATE OR REPLACE VIEW public.pipeline_performance AS
-- Jobs timing
SELECT
    'jobs' AS metric_source,
    j.id::text AS entity_id,
    NULL::uuid AS session_id,
    j.type AS scan_type,
    j.status,
    j.started_at,
    j.finished_at AS finished_at,
    EXTRACT(EPOCH FROM (j.finished_at - j.started_at)) AS duration_seconds
FROM public.jobs j
WHERE j.started_at IS NOT NULL

UNION ALL

-- Tasks timing
SELECT
    'tasks' AS metric_source,
    t.id::text AS entity_id,
    NULL::uuid AS session_id,
    t.type AS scan_type,
    t.status,
    t.started_at,
    t.finished_at AS finished_at,
    EXTRACT(EPOCH FROM (t.finished_at - t.started_at)) AS duration_seconds
FROM public.tasks t
WHERE t.started_at IS NOT NULL

UNION ALL

-- Agent sessions timing
SELECT
    'agent_sessions' AS metric_source,
    a.id::text AS entity_id,
    a.id AS session_id,
    'pentest_session' AS scan_type,
    a.status,
    a.created_at AS started_at,
    a.end_time AS finished_at,
    EXTRACT(EPOCH FROM (a.end_time - a.created_at)) AS duration_seconds
FROM public.agent_sessions a

UNION ALL

-- Playwright scans timing
SELECT
    'playwright_scans' AS metric_source,
    ps.id::text AS entity_id,
    NULL::uuid AS session_id,
    'playwright' AS scan_type,
    ps.status,
    ps.start_time AS started_at,
    ps.end_time AS finished_at,
    EXTRACT(EPOCH FROM (ps.end_time - ps.start_time)) AS duration_seconds
FROM public.playwright_scans ps
WHERE ps.start_time IS NOT NULL

UNION ALL

-- Session scan metrics (persisted tracker data)
SELECT
    'session_scan_metrics' AS metric_source,
    ssm.id::text AS entity_id,
    ssm.session_id,
    ssm.scan_type,
    ssm.status,
    ssm.started_at,
    ssm.completed_at AS finished_at,
    ssm.duration_seconds
FROM public.session_scan_metrics ssm

UNION ALL

-- Exploit results timing
SELECT
    'exploit_results' AS metric_source,
    er.id::text AS entity_id,
    pe.session_id,
    'exploit' AS scan_type,
    CASE WHEN er.success THEN 'completed' ELSE 'failed' END AS status,
    er.executed_at AS started_at,
    er.completed_at AS finished_at,
    er.execution_time_ms / 1000.0 AS duration_seconds
FROM public.exploit_results er
JOIN public.pending_exploits pe ON er.pending_exploit_id = pe.id
WHERE er.executed_at IS NOT NULL;

-- GRPO training infrastructure tables
\i /docker-entrypoint-initdb.d/grpo_migration.sql

-- End of file
