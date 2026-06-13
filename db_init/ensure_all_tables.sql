-- ensure_all_tables.sql
-- ============================================================================
-- SINGLE COMPREHENSIVE SCHEMA FILE for the scans database
-- Ensures ALL required tables, indexes, triggers, and views exist.
-- Safe to run multiple times (uses IF NOT EXISTS / DO $$ guards).
-- Run this on a fresh platform to guarantee full schema creation.
-- ============================================================================
-- Last updated: 2026-04-12
-- Tables: 78+  |  Database: scans
-- ============================================================================

\connect scans

-- Required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

DO $$ BEGIN
  CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'pgvector extension not available: %', SQLERRM;
END $$;

-- ===============================
-- Helper function: _touch_updated_at
-- ===============================
CREATE OR REPLACE FUNCTION public._touch_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- TIER 0: Foundation tables (no foreign keys to other app tables)
-- ============================================================================

-- assets
CREATE TABLE IF NOT EXISTS public.assets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ip         inet NOT NULL,
    hostname   text,
    env        text,
    tags       text[],
    first_seen timestamptz DEFAULT now(),
    last_seen  timestamptz DEFAULT now(),
    os         text
);
-- Allow multiple hostnames per IP (virtual hosts / shared hosting)
-- Migration: drop old UNIQUE on ip alone, add composite unique
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_ip_key') THEN
        ALTER TABLE public.assets DROP CONSTRAINT assets_ip_key;
    END IF;
    -- Older deployments may also have a different unique-on-ip constraint name
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'assets_ip_unique') THEN
        ALTER TABLE public.assets DROP CONSTRAINT assets_ip_unique;
    END IF;
END $$;
-- Some early deployments created the unique-on-ip as a bare INDEX rather than a
-- table CONSTRAINT, so DROP CONSTRAINT can't remove it. Drop the index directly.
DROP INDEX IF EXISTS public.assets_ip_unique;
CREATE UNIQUE INDEX IF NOT EXISTS ix_assets_ip_hostname ON public.assets(ip, COALESCE(hostname, ''));
CREATE INDEX IF NOT EXISTS ix_assets_ip ON public.assets(ip);
CREATE INDEX IF NOT EXISTS ix_assets_hostname ON public.assets(hostname);

-- Migration: ensure assets has all required columns
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS hostname text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS last_seen timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS modified_by text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local'; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS env text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS tags text[] DEFAULT '{}'::text[]; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS first_seen timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$;
-- content_hash: lets cloud_import resume detect when a re-uploaded file's
-- contents have changed even though the filename matches. Populated by
-- parsers (zip → CRC32 from header, dir → MD5 of bytes). NULL on legacy
-- rows; resume check treats NULL as "trust the filename match" for
-- backward compat.
DO $$ BEGIN ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS content_hash text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_assets_content_hash ON public.assets(content_hash) WHERE content_hash IS NOT NULL;

-- provider tagging: which cloud provider(s) host this asset. Populated by
-- ETL parsers when they see CNAMEs to *.amazonaws.com, TLS certs from
-- Amazon, ASN lookups returning Amazon, etc. Multi-valued because a CDN
-- can sit in front of a different-provider origin (Cloudflare → AWS).
-- provider_evidence keeps {provider: [reason, ...]} so operators can see
-- *why* the tag was applied (e.g. cname:cloudfront.net, asn:16509).
DO $$ BEGIN
    ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS provider text[] DEFAULT '{}'::text[];
    ALTER TABLE public.assets ADD COLUMN IF NOT EXISTS provider_evidence jsonb DEFAULT '{}'::jsonb;
EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_assets_provider_gin ON public.assets USING GIN(provider);

-- scans
CREATE TABLE IF NOT EXISTS public.scans (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tool        text,
    profile     text,
    started_at  timestamptz DEFAULT now(),
    finished_at timestamptz,
    args        text,
    metadata    jsonb DEFAULT '{}'::jsonb
);

-- ============================================================================
-- TIER 1: Tables that reference assets and/or scans
-- ============================================================================

-- ports
CREATE TABLE IF NOT EXISTS public.ports (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id   uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    proto      text NOT NULL,
    port       integer NOT NULL,
    service    text,
    product    text,
    version    text,
    banner     text,
    first_seen timestamptz DEFAULT now(),
    last_seen  timestamptz DEFAULT now(),
    is_open    boolean DEFAULT true,
    created_at timestamptz DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ports_asset_proto_port_scans ON public.ports(asset_id, proto, port);

-- Migration: ensure ports has all required columns
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS is_open boolean DEFAULT true; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS product text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS version text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS banner text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS modified_by text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.ports ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local'; EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- findings
CREATE TABLE IF NOT EXISTS public.findings (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title      text,
    severity   text,
    asset_id   uuid REFERENCES public.assets(id),
    port       integer,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    details    jsonb
);

-- port_observation
CREATE TABLE IF NOT EXISTS public.port_observation (
    id          uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_id     uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    asset_id    uuid REFERENCES public.assets(id) ON DELETE SET NULL,
    ip          inet NOT NULL,
    proto       text NOT NULL CHECK (proto IN ('tcp','udp')),
    port        integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    state       text,
    ttl         integer,
    banner      text,
    service     jsonb DEFAULT '{}'::jsonb,
    tool        text NOT NULL,
    raw         jsonb DEFAULT '{}'::jsonb,
    observed_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS port_observation_asset_proto_port_idx ON public.port_observation(asset_id, proto, port);
CREATE INDEX IF NOT EXISTS port_observation_ip_proto_port_idx ON public.port_observation(ip, proto, port);
CREATE INDEX IF NOT EXISTS port_obs_raw_gin ON public.port_observation USING GIN (raw);
CREATE INDEX IF NOT EXISTS port_obs_service_gin ON public.port_observation USING GIN (service);

-- raw_output
CREATE TABLE IF NOT EXISTS public.raw_output (
    id           uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_id      uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    tool         text NOT NULL,
    content      bytea NOT NULL,
    content_type text NOT NULL,
    created_at   timestamptz DEFAULT now()
);

-- scan_targets
CREATE TABLE IF NOT EXISTS public.scan_targets (
    id       uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_id  uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    target   text NOT NULL,
    asset_id uuid REFERENCES public.assets(id) ON DELETE SET NULL,
    note     text
);
CREATE INDEX IF NOT EXISTS scan_targets_scan_id_idx ON public.scan_targets(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_targets_target ON public.scan_targets(target);

-- finding_evidence
CREATE TABLE IF NOT EXISTS public.finding_evidence (
    id                  uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    finding_id          uuid NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
    scan_id             uuid REFERENCES public.scans(id) ON DELETE SET NULL,
    port_observation_id uuid REFERENCES public.port_observation(id) ON DELETE SET NULL,
    snippet             text,
    blob                bytea,
    metadata            jsonb DEFAULT '{}'::jsonb,
    created_at          timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_evidence_meta_gin ON public.finding_evidence USING GIN (metadata);

-- cve cache
CREATE TABLE IF NOT EXISTS public.cve (
    id            text PRIMARY KEY,
    summary       text,
    cvss          numeric,
    published     timestamptz,
    last_modified timestamptz,
    refs          jsonb DEFAULT '{}'::jsonb
);

-- ============================================================================
-- TIER 2: Feature tables (web, vulns, recon, credentials, playwright, ZAP)
-- ============================================================================

-- web_findings
CREATE TABLE IF NOT EXISTS public.web_findings (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url         text NOT NULL,
    source      text NOT NULL,
    issue_type  text,
    name        text,
    severity    text CHECK (severity IN ('info','low','medium','high','critical','error','recon') OR severity IS NULL),
    evidence    text,
    status_code integer,
    method      text,
    payload     text,
    description text,
    solution    text,
    reference   text,
    confidence  text,
    tags        jsonb,
    cwe         text[],
    refs        jsonb DEFAULT '{}'::jsonb,
    request_data  text,
    response_data text,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS port integer;
CREATE INDEX IF NOT EXISTS idx_web_findings_asset_id ON public.web_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_web_findings_url ON public.web_findings(url);
CREATE INDEX IF NOT EXISTS idx_web_findings_source ON public.web_findings(source);
CREATE INDEX IF NOT EXISTS idx_web_findings_severity ON public.web_findings(severity);
CREATE INDEX IF NOT EXISTS idx_web_findings_created_at ON public.web_findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_web_findings_port ON public.web_findings(port);

-- Auto-extract port from URL on insert/update if not explicitly set
CREATE OR REPLACE FUNCTION public._extract_port_from_url() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.port IS NULL AND NEW.url IS NOT NULL THEN
    -- Try explicit port in URL  e.g. https://host:8443/path
    NEW.port := (substring(NEW.url from '://[^/:]+:(\d+)'))::integer;
    -- Fall back to scheme default
    IF NEW.port IS NULL THEN
      IF NEW.url LIKE 'https://%' THEN NEW.port := 443;
      ELSIF NEW.url LIKE 'http://%' THEN NEW.port := 80;
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_web_findings_port ON public.web_findings;
CREATE TRIGGER trg_web_findings_port
  BEFORE INSERT OR UPDATE ON public.web_findings
  FOR EACH ROW EXECUTE FUNCTION public._extract_port_from_url();

-- Backfill port for existing rows that have NULL port
UPDATE public.web_findings SET port = (substring(url from '://[^/:]+:(\d+)'))::integer
WHERE port IS NULL AND url ~ '://[^/:]+:\d+';
UPDATE public.web_findings SET port = 443
WHERE port IS NULL AND url LIKE 'https://%';
UPDATE public.web_findings SET port = 80
WHERE port IS NULL AND url LIKE 'http://%';

-- Backfill port in vulns metadata for tools that didn't store it
UPDATE public.vulns SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{port}', to_jsonb(p.port))
FROM public.ports p WHERE vulns.port_id = p.id AND (vulns.metadata->>'port') IS NULL;

UPDATE public.vulns SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{port}', '22'::jsonb)
WHERE script LIKE 'ssh-audit:%' AND port_id IS NULL AND (metadata->>'port') IS NULL;

UPDATE public.vulns SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{port}', '443'::jsonb)
WHERE script LIKE ANY(ARRAY['sslscan:%','testssl:%','sslyze:%']) AND port_id IS NULL AND (metadata->>'port') IS NULL;

-- discovered_params (Paramalyzer-style catalog from katana crawls)
CREATE TABLE IF NOT EXISTS public.discovered_params (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id         uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url_pattern      text NOT NULL,
    param_name       text NOT NULL,
    param_type       text DEFAULT 'string',
    http_method      text DEFAULT 'GET',
    param_location   text DEFAULT 'query',
    sample_values    text[],
    occurrence_count integer DEFAULT 1,
    discovery_source text DEFAULT 'katana',
    first_seen       timestamptz DEFAULT now(),
    last_seen        timestamptz DEFAULT now(),
    UNIQUE(url_pattern, param_name, http_method, param_location)
);
CREATE INDEX IF NOT EXISTS idx_discovered_params_asset ON public.discovered_params(asset_id);
CREATE INDEX IF NOT EXISTS idx_discovered_params_name ON public.discovered_params(param_name);
CREATE INDEX IF NOT EXISTS idx_discovered_params_url ON public.discovered_params(url_pattern);

-- vulns
CREATE TABLE IF NOT EXISTS public.vulns (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id   uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    port_id    uuid REFERENCES public.ports(id) ON DELETE CASCADE,
    script     text NOT NULL,
    output     text NOT NULL,
    severity   text CHECK (severity IN ('info','low','medium','high','critical')),
    cve        text[],
    cvss       numeric,
    refs       jsonb DEFAULT '{}'::jsonb,
    metadata   jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
-- Migration: ensure vulns has all required columns
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS title text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS workflow_status text DEFAULT 'new'; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS assigned_to text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS verified_by text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS verified_at timestamptz; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_vulns_asset_id ON public.vulns(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulns_port_id ON public.vulns(port_id);
CREATE INDEX IF NOT EXISTS idx_vulns_script ON public.vulns(script);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON public.vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cve_gin ON public.vulns USING GIN (cve);
CREATE INDEX IF NOT EXISTS idx_vulns_created_at ON public.vulns(created_at DESC);

-- scan_recommendations
CREATE TABLE IF NOT EXISTS public.scan_recommendations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    ip          inet,
    service     text,
    banner      text,
    scanner     text NOT NULL,
    action      text,
    script      text,
    template    text,
    source      text NOT NULL DEFAULT 'rules',
    model       text,
    extra       jsonb DEFAULT '{}'::jsonb,
    confidence  numeric,
    priority    integer DEFAULT 50,
    status      text DEFAULT 'pending' CHECK (status IN ('pending','queued','running','completed','failed','skipped')),
    executed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_asset_id ON public.scan_recommendations(asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_ip ON public.scan_recommendations(ip);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_scanner ON public.scan_recommendations(scanner);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_status ON public.scan_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_priority ON public.scan_recommendations(priority DESC);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_created_at ON public.scan_recommendations(created_at DESC);

-- scan_recommendations fingerprint column (generated, for dedup)
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

-- credential_findings (Brutus)
CREATE TABLE IF NOT EXISTS public.credential_findings (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id    uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    port_id     uuid REFERENCES public.ports(id) ON DELETE SET NULL,
    ip          inet NOT NULL,
    port        integer NOT NULL,
    protocol    text NOT NULL,
    username    text NOT NULL,
    valid_cred  boolean NOT NULL DEFAULT true,
    auth_type   text DEFAULT 'password',
    severity    text DEFAULT 'critical',
    banner      text,
    duration_ms numeric,
    source      text DEFAULT 'brutus',
    metadata    jsonb DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_credential_findings_asset_id ON public.credential_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_credential_findings_ip ON public.credential_findings(ip);
CREATE INDEX IF NOT EXISTS idx_credential_findings_protocol ON public.credential_findings(protocol);
CREATE INDEX IF NOT EXISTS idx_credential_findings_created_at ON public.credential_findings(created_at DESC);

-- Migration: add secret_type column to credential_findings
DO $$ BEGIN
  ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS secret_type text DEFAULT 'password';
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS idx_credential_findings_secret_type ON public.credential_findings(secret_type);

-- Migration: add discovered_at, last_verified_at, status to credential_findings
DO $$ BEGIN
  ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS discovered_at timestamptz DEFAULT now();
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS last_verified_at timestamptz;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS status text DEFAULT 'unknown'
    CHECK (status IN ('valid','invalid','unknown','remediated'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS idx_credential_findings_status ON public.credential_findings(status);

-- recon_findings (dnsx, tlsx, asnmap, uncover, cloudlist, httpx, subfinder, whatweb)
CREATE TABLE IF NOT EXISTS public.recon_findings (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id     uuid REFERENCES public.assets(id) ON DELETE SET NULL,
    source       text NOT NULL,
    finding_type text NOT NULL,
    target       text NOT NULL,
    data         jsonb NOT NULL,
    severity     text CHECK (severity IN ('info','low','medium','high','critical','error','recon')),
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_recon_findings_source ON public.recon_findings(source);
CREATE INDEX IF NOT EXISTS idx_recon_findings_finding_type ON public.recon_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_recon_findings_target ON public.recon_findings(target);
CREATE INDEX IF NOT EXISTS idx_recon_findings_asset_id ON public.recon_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_recon_findings_created_at ON public.recon_findings(created_at DESC);

-- ===============================
-- Playwright tables
-- ===============================

-- playwright_scans
CREATE TABLE IF NOT EXISTS public.playwright_scans (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id     uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url          text NOT NULL,
    status       text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued','running','completed','failed')),
    start_time   timestamptz,
    end_time     timestamptz,
    browser      text DEFAULT 'chromium',
    viewport     jsonb,
    user_agent   text,
    cookies      jsonb DEFAULT '[]'::jsonb,
    screenshots  integer DEFAULT 0,
    dom_snapshot boolean DEFAULT false,
    console_logs jsonb DEFAULT '[]'::jsonb,
    network_logs jsonb DEFAULT '[]'::jsonb,
    errors       jsonb DEFAULT '[]'::jsonb,
    metadata     jsonb DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_asset_id ON public.playwright_scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_url ON public.playwright_scans(url);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_status ON public.playwright_scans(status);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_created_at ON public.playwright_scans(created_at DESC);

-- playwright_findings
CREATE TABLE IF NOT EXISTS public.playwright_findings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         uuid NOT NULL REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
    asset_id        uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url             text NOT NULL,
    finding_type    text NOT NULL,
    severity        text CHECK (severity IN ('info','low','medium','high','critical')),
    title           text NOT NULL,
    description     text,
    evidence        text,
    location        text,
    remediation     text,
    cwe             text[],
    owasp_category  text,
    refs            jsonb DEFAULT '[]'::jsonb,
    screenshot_id   uuid,
    dom_element     jsonb,
    related_request jsonb,
    confidence      numeric,
    false_positive  boolean DEFAULT false,
    verified        boolean DEFAULT false,
    notes           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_scan_id ON public.playwright_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_asset_id ON public.playwright_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_url ON public.playwright_findings(url);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_type ON public.playwright_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_severity ON public.playwright_findings(severity);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_cwe_gin ON public.playwright_findings USING GIN (cwe);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_created_at ON public.playwright_findings(created_at DESC);

-- playwright_screenshots
CREATE TABLE IF NOT EXISTS public.playwright_screenshots (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id    uuid NOT NULL REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
    url        text NOT NULL,
    viewport   jsonb,
    format     text DEFAULT 'png' CHECK (format IN ('png','jpeg','webp')),
    image_data bytea,
    image_hash text,
    file_size  integer,
    full_page  boolean DEFAULT false,
    selector   text,
    metadata   jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_scan_id ON public.playwright_screenshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_url ON public.playwright_screenshots(url);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_hash ON public.playwright_screenshots(image_hash);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_created_at ON public.playwright_screenshots(created_at DESC);

-- dom_analysis
CREATE TABLE IF NOT EXISTS public.dom_analysis (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           uuid NOT NULL REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
    asset_id          uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url               text NOT NULL,
    forms_count       integer DEFAULT 0,
    forms             jsonb DEFAULT '[]'::jsonb,
    inputs_count      integer DEFAULT 0,
    cookies           jsonb DEFAULT '[]'::jsonb,
    local_storage     jsonb DEFAULT '{}'::jsonb,
    session_storage   jsonb DEFAULT '{}'::jsonb,
    javascript_libs   jsonb DEFAULT '[]'::jsonb,
    csp_header        text,
    cors_enabled      boolean,
    cors_config       jsonb DEFAULT '{}'::jsonb,
    security_headers  jsonb DEFAULT '{}'::jsonb,
    external_scripts  jsonb DEFAULT '[]'::jsonb,
    mixed_content     boolean DEFAULT false,
    websockets        jsonb DEFAULT '[]'::jsonb,
    postmessage_usage boolean DEFAULT false,
    dom_snapshot      text,
    metadata          jsonb DEFAULT '{}'::jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_scan_id ON public.dom_analysis(scan_id);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_asset_id ON public.dom_analysis(asset_id);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_url ON public.dom_analysis(url);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_created_at ON public.dom_analysis(created_at DESC);

-- content_extractions (content intelligence from spidered pages)
CREATE TABLE IF NOT EXISTS public.content_extractions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         uuid REFERENCES public.playwright_scans(id) ON DELETE CASCADE,
    asset_id        uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url             text NOT NULL,
    emails          jsonb DEFAULT '[]'::jsonb,
    names           jsonb DEFAULT '[]'::jsonb,
    internal_paths  jsonb DEFAULT '[]'::jsonb,
    api_endpoints   jsonb DEFAULT '[]'::jsonb,
    exposed_keys    jsonb DEFAULT '[]'::jsonb,
    tech_indicators jsonb DEFAULT '[]'::jsonb,
    comments        jsonb DEFAULT '[]'::jsonb,
    hidden_inputs   jsonb DEFAULT '[]'::jsonb,
    js_configs      jsonb DEFAULT '{}'::jsonb,
    interesting_files jsonb DEFAULT '[]'::jsonb,
    file_metadata   jsonb DEFAULT '[]'::jsonb,
    login_pages     jsonb DEFAULT '[]'::jsonb,
    word_corpus     text,
    metadata        jsonb DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_content_extractions_scan_id ON public.content_extractions(scan_id);
CREATE INDEX IF NOT EXISTS idx_content_extractions_asset_id ON public.content_extractions(asset_id);
CREATE INDEX IF NOT EXISTS idx_content_extractions_url ON public.content_extractions(url);
CREATE INDEX IF NOT EXISTS idx_content_extractions_created_at ON public.content_extractions(created_at DESC);

-- content_intel_patterns (user-defined extraction patterns)
CREATE TABLE IF NOT EXISTS public.content_intel_patterns (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    category    text NOT NULL CHECK (category IN (
                  'emails','secrets','paths','api_endpoints','tech','comments','custom')),
    name        text NOT NULL,
    pattern     text NOT NULL,
    label       text,
    enabled     boolean DEFAULT true,
    is_builtin  boolean DEFAULT false,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_content_intel_patterns_category ON public.content_intel_patterns(category);
CREATE INDEX IF NOT EXISTS idx_content_intel_patterns_enabled ON public.content_intel_patterns(enabled);

-- zap_sessions
CREATE TABLE IF NOT EXISTS public.zap_sessions (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    playwright_scan_id uuid REFERENCES public.playwright_scans(id) ON DELETE SET NULL,
    web_scan_job_id    uuid,
    session_name       text NOT NULL,
    zap_api_key        text,
    context_name       text,
    sites              jsonb DEFAULT '[]'::jsonb,
    spider_completed   boolean DEFAULT false,
    ascan_completed    boolean DEFAULT false,
    alerts_count       integer DEFAULT 0,
    session_file       text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_zap_sessions_playwright_scan_id ON public.zap_sessions(playwright_scan_id);
CREATE INDEX IF NOT EXISTS idx_zap_sessions_created_at ON public.zap_sessions(created_at DESC);

-- kb_service_overrides (Knowledge Base user edits)
CREATE TABLE IF NOT EXISTS public.kb_service_overrides (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name text NOT NULL UNIQUE,
    data         jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_kb_service_overrides_name ON public.kb_service_overrides(service_name);

-- scan_tool_feedback (durable feedback loop: operator/agent judgments that
-- steer which tools the recommender picks). The recommender reads active rows
-- and applies them as policies when generating recs.
--   verdict 'suppress'     → drop matching recs (scanner [+ selector glob]); service NULL = global
--   verdict 'add_tool'     → inject a tool rec for a service (payload: {name, action, command})
--   verdict 'add_overlap'  → tag matching recs into an overlap group (payload: {group})
CREATE TABLE IF NOT EXISTS public.scan_tool_feedback (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service     text,                       -- e.g. 'http'; NULL = applies to all services
    scanner     text,                       -- e.g. 'metasploit', 'vulnx' (NULL for add_tool)
    selector    text,                       -- glob vs rec script/module (NULL = any)
    verdict     text NOT NULL CHECK (verdict IN ('suppress','add_tool','add_overlap')),
    payload     jsonb NOT NULL DEFAULT '{}'::jsonb,
    reason      text,
    created_by  text,
    active      boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_tool_feedback_active ON public.scan_tool_feedback(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_scan_tool_feedback_service ON public.scan_tool_feedback(service);

-- attack_vectors (MITRE ATT&CK "vector map": findings mapped to techniques +
-- a unified risk score for attack-path prioritization). Populated by
-- app/rag-api/attack_vectors.py from findings/vulns/web_findings/recon_findings,
-- using knowledge/mitre/attack_map.yaml. Consumed by the AI agents (ranked
-- next-best-action), the Attack Map UI, and the webhook bus.
CREATE TABLE IF NOT EXISTS public.attack_vectors (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     uuid,
    asset_id          uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    finding_source    text NOT NULL,          -- vuln | web_finding | recon_finding
    finding_id        uuid NOT NULL,
    technique         text NOT NULL,          -- MITRE technique id (e.g. T1190)
    technique_name    text,
    tactic            text,                   -- MITRE tactic (e.g. initial_access)
    kill_chain_phase  text,
    severity          text,
    risk_score        numeric NOT NULL DEFAULT 0,   -- 0..100
    risk_factors      jsonb NOT NULL DEFAULT '{}'::jsonb,  -- per-term breakdown
    rationale         text,
    target            text,                   -- ip/host/url for display
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (finding_source, finding_id, technique)
);
CREATE INDEX IF NOT EXISTS idx_attack_vectors_engagement ON public.attack_vectors(engagement_id);
CREATE INDEX IF NOT EXISTS idx_attack_vectors_risk ON public.attack_vectors(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_attack_vectors_tactic ON public.attack_vectors(tactic);
CREATE INDEX IF NOT EXISTS idx_attack_vectors_asset ON public.attack_vectors(asset_id);

-- ============================================================================
-- TIER 3: Job / Task scheduling
-- ============================================================================

-- jobs
CREATE TABLE IF NOT EXISTS public.jobs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type            text NOT NULL,
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','finished','failed','canceled')),
    params          jsonb NOT NULL DEFAULT '{}'::jsonb,
    total_tasks     integer NOT NULL DEFAULT 0,
    finished_tasks  integer NOT NULL DEFAULT 0,
    error           text,
    idempotency_key text UNIQUE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz
);
DO $$ BEGIN ALTER TABLE public.jobs ADD COLUMN IF NOT EXISTS result jsonb DEFAULT '{}'::jsonb; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.jobs ADD COLUMN IF NOT EXISTS progress jsonb DEFAULT '{}'::jsonb; EXCEPTION WHEN OTHERS THEN NULL; END $$;
-- progress_updated_at lets the auto-sweeper detect stuck running jobs without
-- relying on the row's created_at (too coarse). Bumped from the parser's
-- progress callback every flush; sweeper marks status='failed' if it's been
-- >5 min since the last bump.
DO $$ BEGIN ALTER TABLE public.jobs ADD COLUMN IF NOT EXISTS progress_updated_at timestamptz; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_jobs_running_progress ON public.jobs(status, progress_updated_at) WHERE status = 'running';
-- Drop legacy single-value CHECK on jobs.type (early schema artifact). The application
-- emits many job types (masscan-nmap, microburst-ingest, pipeline, etc.) so a
-- whitelist CHECK breaks future ingest paths whenever a new type is added.
DO $$ BEGIN ALTER TABLE public.jobs DROP CONSTRAINT IF EXISTS jobs_type_check; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_jobs_status ON public.jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON public.jobs(created_at DESC);

-- tasks (sub-units of jobs)
CREATE TABLE IF NOT EXISTS public.tasks (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id      uuid NOT NULL REFERENCES public.jobs(id) ON DELETE CASCADE,
    type        text NOT NULL,
    target_host inet,
    target_port integer,
    proto       text,
    status      text NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued','running','finished','failed','canceled')),
    attempt     integer NOT NULL DEFAULT 0,
    last_error  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    started_at  timestamptz,
    finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_tasks_job ON public.tasks(job_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON public.tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_job_status ON public.tasks(job_id, status);

-- ============================================================================
-- TIER 4: Agent / session tables
-- ============================================================================

-- agent_sessions
CREATE TABLE IF NOT EXISTS public.agent_sessions (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_name       text NOT NULL,
    target_description text NOT NULL,
    status             text NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active','completed','failed','stopped','stalled')),
    configuration      jsonb DEFAULT '{}'::jsonb,
    summary            text,
    metadata           jsonb DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    end_time           timestamptz,
    parent_session_id  uuid REFERENCES public.agent_sessions(id)
);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON public.agent_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_created_at ON public.agent_sessions(created_at DESC);

-- agent_messages
CREATE TABLE IF NOT EXISTS public.agent_messages (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id uuid NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
    agent_name text NOT NULL,
    role       text NOT NULL,
    content    text NOT NULL,
    metadata   jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_messages_session_id ON public.agent_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_messages_agent_name ON public.agent_messages(agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_messages_created_at ON public.agent_messages(created_at DESC);

-- session_scan_metrics
CREATE TABLE IF NOT EXISTS public.session_scan_metrics (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id       uuid NOT NULL,
    scan_type        text NOT NULL,
    scan_phase       text,
    job_id           text,
    status           text NOT NULL DEFAULT 'running',
    started_at       timestamptz,
    completed_at     timestamptz,
    duration_seconds numeric,
    params           jsonb DEFAULT '{}'::jsonb,
    result_summary   jsonb DEFAULT '{}'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_session_id ON public.session_scan_metrics(session_id);
CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_scan_type ON public.session_scan_metrics(scan_type);
CREATE INDEX IF NOT EXISTS idx_session_scan_metrics_created_at ON public.session_scan_metrics(created_at DESC);

-- llm_request_metrics
CREATE TABLE IF NOT EXISTS public.llm_request_metrics (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id        uuid,
    agent_name        text,
    caller            text,
    model_name        text NOT NULL,
    prompt_tokens     integer,
    completion_tokens integer,
    total_tokens      integer,
    tokens_per_sec    numeric,
    latency_ms        numeric NOT NULL,
    has_tool_calls    boolean NOT NULL DEFAULT false,
    tool_call_count   integer DEFAULT 0,
    tool_names        text[],
    is_error          boolean NOT NULL DEFAULT false,
    error_message     text,
    request_params    jsonb DEFAULT '{}'::jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.llm_request_metrics ALTER COLUMN session_id DROP NOT NULL;
ALTER TABLE public.llm_request_metrics ADD COLUMN IF NOT EXISTS caller text;
ALTER TABLE public.llm_request_metrics ADD COLUMN IF NOT EXISTS tokens_per_sec numeric;
CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_session_id ON public.llm_request_metrics(session_id);
CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_model_name ON public.llm_request_metrics(model_name);
CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_agent_name ON public.llm_request_metrics(agent_name);
CREATE INDEX IF NOT EXISTS idx_llm_request_metrics_created_at ON public.llm_request_metrics(created_at DESC);

-- prompt_configs (named LLM prompt configuration sets)
CREATE TABLE IF NOT EXISTS public.prompt_configs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text,
    prompts     jsonb NOT NULL,
    is_active   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_prompt_configs_name ON public.prompt_configs(name);
CREATE INDEX IF NOT EXISTS idx_prompt_configs_active ON public.prompt_configs(is_active) WHERE is_active = true;

-- ============================================================================
-- TIER 5: Exploit workflow tables
-- ============================================================================

-- pending_exploits
CREATE TABLE IF NOT EXISTS public.pending_exploits (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id           uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    port_id            uuid REFERENCES public.ports(id) ON DELETE SET NULL,
    source             text NOT NULL CHECK (source IN ('exploitdb', 'metasploit')),
    exploit_id         text NOT NULL,
    exploit_title      text NOT NULL,
    exploit_type       text CHECK (exploit_type IN ('rce', 'auth_bypass', 'info_disclosure', 'other')),
    target_ip          inet NOT NULL,
    target_port        integer,
    target_service     text,
    target_version     text,
    customized_command text NOT NULL,
    parameters         jsonb DEFAULT '{}'::jsonb,
    match_confidence   numeric,
    match_reasoning    text,
    status             text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','approved','rejected','executed','failed')),
    requested_by       text,
    reviewed_by        text,
    reviewed_at        timestamptz,
    rejection_reason   text,
    session_id         uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
    metadata           jsonb DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pending_exploits_status ON public.pending_exploits(status);
CREATE INDEX IF NOT EXISTS idx_pending_exploits_asset_id ON public.pending_exploits(asset_id);
CREATE INDEX IF NOT EXISTS idx_pending_exploits_session_id ON public.pending_exploits(session_id);
CREATE INDEX IF NOT EXISTS idx_pending_exploits_created_at ON public.pending_exploits(created_at DESC);

-- Expand exploit_type CHECK to include web exploit categories
DO $$ BEGIN
  ALTER TABLE public.pending_exploits DROP CONSTRAINT IF EXISTS pending_exploits_exploit_type_check;
  ALTER TABLE public.pending_exploits ADD CONSTRAINT pending_exploits_exploit_type_check
    CHECK (exploit_type IN (
      'rce', 'auth_bypass', 'info_disclosure', 'other',
      'sqli', 'xss', 'lfi', 'rfi', 'ssrf', 'command_injection',
      'file_upload', 'deserialization', 'xxe', 'csrf', 'webapp_other'
    ));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Add exploit_category for higher-level classification
DO $$ BEGIN
  ALTER TABLE public.pending_exploits ADD COLUMN IF NOT EXISTS exploit_category text DEFAULT 'other';
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE public.pending_exploits ADD COLUMN IF NOT EXISTS edb_id text;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS idx_pending_exploits_category ON public.pending_exploits(exploit_category);

-- Fix schema drift: older installs created target_ip as text; code and this
-- schema expect inet (exploit_watcher compares with %s::inet).
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'pending_exploits'
      AND column_name = 'target_ip' AND data_type = 'text'
  ) THEN
    ALTER TABLE public.pending_exploits
      ALTER COLUMN target_ip TYPE inet USING NULLIF(target_ip, '')::inet;
  END IF;
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 'Could not convert pending_exploits.target_ip to inet: %', SQLERRM;
END $$;

-- exploit_results
CREATE TABLE IF NOT EXISTS public.exploit_results (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pending_exploit_id uuid NOT NULL REFERENCES public.pending_exploits(id) ON DELETE CASCADE,
    executed_at        timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz,
    execution_time_ms  integer,
    success            boolean NOT NULL DEFAULT false,
    output             text,
    parsed_result      jsonb DEFAULT '{}'::jsonb,
    session_type       text,
    session_id         text,
    artifacts          jsonb DEFAULT '[]'::jsonb,
    executor_container text,
    audit_log          jsonb DEFAULT '[]'::jsonb,
    validation_status  text,
    validation_output  text,
    parsed_validation  jsonb,
    access_level       text,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_exploit_results_pending_id ON public.exploit_results(pending_exploit_id);
CREATE INDEX IF NOT EXISTS idx_exploit_results_success ON public.exploit_results(success);
CREATE INDEX IF NOT EXISTS idx_exploit_results_executed_at ON public.exploit_results(executed_at DESC);

-- msf_modules (Metasploit module cache)
CREATE TABLE IF NOT EXISTS public.msf_modules (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    module_path      text UNIQUE NOT NULL,
    module_type      text NOT NULL CHECK (module_type IN ('exploit','auxiliary','post','payload','encoder','nop')),
    name             text NOT NULL,
    description      text,
    rank             text,
    platforms        text[],
    architectures    text[],
    targets          jsonb DEFAULT '[]'::jsonb,
    cve              text[],
    edb_id           text[],
    required_options jsonb DEFAULT '{}'::jsonb,
    optional_options jsonb DEFAULT '{}'::jsonb,
    author           text[],
    disclosure_date  date,
    last_updated     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_msf_modules_type ON public.msf_modules(module_type);
CREATE INDEX IF NOT EXISTS idx_msf_modules_cve_gin ON public.msf_modules USING GIN (cve);
CREATE INDEX IF NOT EXISTS idx_msf_modules_platforms_gin ON public.msf_modules USING GIN (platforms);
DO $$ BEGIN
  CREATE INDEX idx_msf_modules_name_trgm ON public.msf_modules USING GIN (name gin_trgm_ops);
EXCEPTION WHEN duplicate_table THEN NULL;
END $$;

-- active_listeners (kali-listener service)
CREATE TABLE IF NOT EXISTS public.active_listeners (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    listener_type      text CHECK (listener_type IN ('nc', 'socat', 'meterpreter')),
    port               integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    status             text DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'stopped')),
    pid                integer,
    pending_exploit_id uuid,
    started_at         timestamptz DEFAULT now(),
    stopped_at         timestamptz
);
CREATE INDEX IF NOT EXISTS idx_active_listeners_status ON public.active_listeners(status);
CREATE INDEX IF NOT EXISTS idx_active_listeners_port ON public.active_listeners(port);
CREATE INDEX IF NOT EXISTS idx_active_listeners_pending_exploit ON public.active_listeners(pending_exploit_id);

-- exploit_callbacks (reverse shell callback tracking)
CREATE TABLE IF NOT EXISTS public.exploit_callbacks (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pending_exploit_id  uuid,
    listener_id         uuid REFERENCES public.active_listeners(id) ON DELETE SET NULL,
    callback_type       text CHECK (callback_type IN ('reverse_shell', 'meterpreter')),
    validation_status   text DEFAULT 'pending' CHECK (validation_status IN ('pending', 'received', 'validated', 'failed')),
    validation_commands jsonb DEFAULT '["whoami", "id", "hostname"]'::jsonb,
    validation_output   text,
    parsed_validation   jsonb,
    received_at         timestamptz
);
CREATE INDEX IF NOT EXISTS idx_exploit_callbacks_pending_exploit ON public.exploit_callbacks(pending_exploit_id);
CREATE INDEX IF NOT EXISTS idx_exploit_callbacks_listener ON public.exploit_callbacks(listener_id);
CREATE INDEX IF NOT EXISTS idx_exploit_callbacks_status ON public.exploit_callbacks(validation_status);

-- tool_executions (pentest tool execution tracking)
CREATE TABLE IF NOT EXISTS public.tool_executions (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tool           text NOT NULL,
    command        text NOT NULL,
    target         text NOT NULL,
    port           integer,
    scan_id        uuid REFERENCES public.scans(id) ON DELETE SET NULL,
    service        text,
    status         text DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timeout')),
    exit_code      integer,
    output         text,
    error          text,
    parsed_results jsonb,
    started_at     timestamptz DEFAULT now(),
    completed_at   timestamptz
);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON public.tool_executions(tool);
CREATE INDEX IF NOT EXISTS idx_tool_executions_target ON public.tool_executions(target);
CREATE INDEX IF NOT EXISTS idx_tool_executions_status ON public.tool_executions(status);
CREATE INDEX IF NOT EXISTS idx_tool_executions_scan_id ON public.tool_executions(scan_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_started_at ON public.tool_executions(started_at DESC);

-- ============================================================================
-- TIER 6: Webhooks
-- ============================================================================

-- webhooks
CREATE TABLE IF NOT EXISTS public.webhooks (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL,
    url           text NOT NULL,
    secret        text,
    enabled       boolean DEFAULT true,
    event_types   text[] DEFAULT ARRAY['scan_completed', 'finding_high'],
    sources       text[],
    severities    text[],
    max_retries   integer DEFAULT 3,
    timeout_ms    integer DEFAULT 5000,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_success  timestamptz,
    failure_count integer DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON public.webhooks(enabled);
CREATE INDEX IF NOT EXISTS idx_webhooks_created_at ON public.webhooks(created_at DESC);

-- webhook_events (delivery tracking)
CREATE TABLE IF NOT EXISTS public.webhook_events (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id    uuid NOT NULL REFERENCES public.webhooks(id) ON DELETE CASCADE,
    event_type    text NOT NULL,
    payload       jsonb NOT NULL,
    status        text DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed', 'retrying')),
    attempt       integer DEFAULT 0,
    response_code integer,
    error_message text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    delivered_at  timestamptz,
    next_retry    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook_id ON public.webhook_events(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_status ON public.webhook_events(status);
CREATE INDEX IF NOT EXISTS idx_webhook_events_next_retry ON public.webhook_events(next_retry) WHERE status = 'retrying';
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON public.webhook_events(created_at DESC);

-- webhook_deliveries (delivery tracking)
CREATE TABLE IF NOT EXISTS public.webhook_deliveries (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id    uuid,
    event_type    text,
    payload       jsonb,
    status        text DEFAULT 'pending',
    status_code   integer,
    error         text,
    delivered_at  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- agent_tool_calls (agent tool call tracking)
CREATE TABLE IF NOT EXISTS public.agent_tool_calls (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id    uuid,
    agent_name    text,
    tool_name     text,
    arguments     jsonb,
    result        jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- TIER 7: RAG / vector tables
-- ============================================================================

-- exploit_chunks (RAG embeddings for exploit search)
CREATE TABLE IF NOT EXISTS public.exploit_chunks (
    id          bigserial PRIMARY KEY,
    edb_id      integer,
    title       text,
    path        text,
    platform    text,
    type        text,
    source_repo text,
    published   date,
    chunk_id    integer,
    chunk       text,
    embedding   vector(768),
    sha256      text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (edb_id, chunk_id)
);
CREATE INDEX IF NOT EXISTS exploit_chunks_edb_idx ON public.exploit_chunks(edb_id);
CREATE INDEX IF NOT EXISTS exploit_chunks_platform_idx ON public.exploit_chunks(platform);
CREATE INDEX IF NOT EXISTS exploit_chunks_type_idx ON public.exploit_chunks(type);

-- Ensure created_at column exists (may be missing on older tables)
DO $$ BEGIN
  ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS exploit_chunks_created_at_idx ON public.exploit_chunks(created_at DESC);

-- Conditionally create vector index when enough data exists
DO $$
BEGIN
  IF (SELECT COUNT(*) FROM public.exploit_chunks) > 100 THEN
    CREATE INDEX IF NOT EXISTS exploit_chunks_embedding_idx
      ON public.exploit_chunks USING ivfflat (embedding vector_l2_ops) WITH (lists = 100);
  END IF;
EXCEPTION WHEN OTHERS THEN NULL;
END$$;

-- ============================================================================
-- TIER 8: Distributed scanning (Sliver C2 + Chisel)
-- ============================================================================

-- remote_nodes
CREATE TABLE IF NOT EXISTS public.remote_nodes (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL,
    node_type         text NOT NULL CHECK (node_type IN ('sliver', 'chisel', 'ssh')),
    status            text NOT NULL DEFAULT 'offline'
                      CHECK (status IN ('online', 'offline', 'degraded', 'provisioning', 'connecting', 'error')),
    os                text,
    hostname          text,
    internal_ip       inet,
    external_ip       inet,
    network_segment   text,
    proxy_port        integer CHECK (proxy_port IS NULL OR proxy_port BETWEEN 1 AND 65535),
    proxy_type        text DEFAULT 'socks5' CHECK (proxy_type IN ('socks5', 'socks4', 'http')),
    sliver_session_id text,
    chisel_client_id  text,
    capabilities      jsonb DEFAULT '[]'::jsonb,
    metadata          jsonb DEFAULT '{}'::jsonb,
    last_seen         timestamptz,
    first_seen        timestamptz DEFAULT now(),
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_remote_nodes_status ON public.remote_nodes(status);
CREATE INDEX IF NOT EXISTS idx_remote_nodes_node_type ON public.remote_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_remote_nodes_proxy_port ON public.remote_nodes(proxy_port);
CREATE UNIQUE INDEX IF NOT EXISTS ux_remote_nodes_proxy_port ON public.remote_nodes(proxy_port) WHERE proxy_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_remote_nodes_last_seen ON public.remote_nodes(last_seen DESC);

-- Migrate existing CHECK constraints to include 'ssh' node_type and new statuses
DO $$ BEGIN
  ALTER TABLE public.remote_nodes DROP CONSTRAINT IF EXISTS remote_nodes_node_type_check;
  ALTER TABLE public.remote_nodes ADD CONSTRAINT remote_nodes_node_type_check
    CHECK (node_type IN ('sliver', 'chisel', 'ssh'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

DO $$ BEGIN
  ALTER TABLE public.remote_nodes DROP CONSTRAINT IF EXISTS remote_nodes_status_check;
  ALTER TABLE public.remote_nodes ADD CONSTRAINT remote_nodes_status_check
    CHECK (status IN ('online', 'offline', 'degraded', 'provisioning', 'connecting',
                       'error', 'rotating', 'disabled'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Future WireGuard migration scaffolding. tunnel_method='ssh' (the default)
-- is the existing behavior — autossh SOCKS forwarder. 'wireguard' will route
-- the per-node SOCKS port through a WG peer once Docs/WIREGUARD_MIGRATION.md
-- is followed. 'hybrid' attempts WG first and falls back to ssh.
DO $$ BEGIN
  ALTER TABLE public.remote_nodes ADD COLUMN IF NOT EXISTS tunnel_method text DEFAULT 'ssh'
    CHECK (tunnel_method IN ('ssh', 'wireguard', 'hybrid'));
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
ALTER TABLE public.remote_nodes ADD COLUMN IF NOT EXISTS wg_public_key  text;
ALTER TABLE public.remote_nodes ADD COLUMN IF NOT EXISTS wg_assigned_ip text;
ALTER TABLE public.remote_nodes ADD COLUMN IF NOT EXISTS installation_status text CHECK (installation_status IN ('pending', 'success', 'failed', 'not_attempted'));
ALTER TABLE public.remote_nodes ADD COLUMN IF NOT EXISTS installation_logs text[];
CREATE INDEX IF NOT EXISTS idx_remote_nodes_tunnel_method
    ON public.remote_nodes(tunnel_method) WHERE tunnel_method <> 'ssh';

-- node_ip_history — tracks every IP assignment/release per node for OpSec audit trail
CREATE TABLE IF NOT EXISTS public.node_ip_history (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id           uuid NOT NULL REFERENCES public.remote_nodes(id) ON DELETE CASCADE,
    ip_address        inet NOT NULL,
    cloud_provider    text NOT NULL CHECK (cloud_provider IN ('digitalocean', 'aws', 'azure', 'manual')),
    cloud_resource_id text,
    region            text,
    assigned_at       timestamptz NOT NULL DEFAULT now(),
    released_at       timestamptz,
    release_reason    text,
    scan_count        integer DEFAULT 0,
    scan_job_ids      uuid[] DEFAULT '{}',
    metadata          jsonb DEFAULT '{}'::jsonb,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_node_ip_history_node_id ON public.node_ip_history(node_id, assigned_at DESC);
CREATE INDEX IF NOT EXISTS idx_node_ip_history_ip ON public.node_ip_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_node_ip_history_active ON public.node_ip_history(node_id) WHERE released_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_node_ip_history_provider ON public.node_ip_history(cloud_provider);

-- node_scan_jobs
CREATE TABLE IF NOT EXISTS public.node_scan_jobs (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id        uuid NOT NULL REFERENCES public.remote_nodes(id) ON DELETE CASCADE,
    scan_type      text NOT NULL,
    job_id         text,
    status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    targets        jsonb DEFAULT '[]'::jsonb,
    parameters     jsonb DEFAULT '{}'::jsonb,
    result_summary jsonb,
    error          text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    completed_at   timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_node_scan_jobs_node_id ON public.node_scan_jobs(node_id);
CREATE INDEX IF NOT EXISTS idx_node_scan_jobs_status ON public.node_scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_node_scan_jobs_created_at ON public.node_scan_jobs(created_at DESC);

-- ad_attack_results
CREATE TABLE IF NOT EXISTS public.ad_attack_results (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id        uuid NOT NULL REFERENCES public.remote_nodes(id) ON DELETE CASCADE,
    attack_type    text NOT NULL,
    status         text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    target_domain  text,
    tool           text,
    command_used   text,
    output         text,
    parsed_results jsonb DEFAULT '{}'::jsonb,
    findings_count integer DEFAULT 0,
    error          text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_node_id ON public.ad_attack_results(node_id);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_attack_type ON public.ad_attack_results(attack_type);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_status ON public.ad_attack_results(status);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_created_at ON public.ad_attack_results(created_at DESC);

-- ============================================================================
-- TIER 9: GRPO training infrastructure
-- ============================================================================

-- grpo_feedback
CREATE TABLE IF NOT EXISTS public.grpo_feedback (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    task_type        text NOT NULL CHECK (task_type IN ('scan_analysis', 'exploit_recommendation', 'agent_decision')),
    user_prompt      text NOT NULL,
    model_response   text NOT NULL,
    system_prompt    text,
    context          jsonb DEFAULT '{}'::jsonb,
    rating           integer CHECK (rating BETWEEN 1 AND 5),
    rating_dimensions jsonb DEFAULT '{}'::jsonb,
    reviewer_id      text,
    review_notes     text,
    session_id       uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
    agent_message_id uuid REFERENCES public.agent_messages(id) ON DELETE SET NULL,
    dataset_version  text,
    used_in_training boolean DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_grpo_feedback_task_type ON public.grpo_feedback(task_type);
CREATE INDEX IF NOT EXISTS idx_grpo_feedback_rating ON public.grpo_feedback(rating);
CREATE INDEX IF NOT EXISTS idx_grpo_feedback_session_id ON public.grpo_feedback(session_id);
CREATE INDEX IF NOT EXISTS idx_grpo_feedback_dataset_version ON public.grpo_feedback(dataset_version);
CREATE INDEX IF NOT EXISTS idx_grpo_feedback_used_in_training ON public.grpo_feedback(used_in_training);
CREATE INDEX IF NOT EXISTS idx_grpo_feedback_created_at ON public.grpo_feedback(created_at DESC);

-- grpo_training_runs
CREATE TABLE IF NOT EXISTS public.grpo_training_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    base_model      text NOT NULL,
    dataset_version text NOT NULL,
    task_types      text[] NOT NULL,
    hyperparameters jsonb NOT NULL DEFAULT '{}'::jsonb,
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    error_message   text,
    metrics         jsonb DEFAULT '{}'::jsonb,
    output_path     text,
    started_at      timestamptz,
    completed_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_grpo_training_runs_status ON public.grpo_training_runs(status);
CREATE INDEX IF NOT EXISTS idx_grpo_training_runs_base_model ON public.grpo_training_runs(base_model);
CREATE INDEX IF NOT EXISTS idx_grpo_training_runs_created_at ON public.grpo_training_runs(created_at DESC);

-- grpo_model_registry
CREATE TABLE IF NOT EXISTS public.grpo_model_registry (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    model_name      text NOT NULL,
    model_format    text NOT NULL CHECK (model_format IN ('gguf', 'safetensors', 'lora')),
    model_path      text NOT NULL,
    base_model      text,
    is_active       boolean DEFAULT false,
    ab_weight       numeric DEFAULT 0.0 CHECK (ab_weight >= 0.0 AND ab_weight <= 1.0),
    eval_metrics    jsonb DEFAULT '{}'::jsonb,
    training_run_id uuid REFERENCES public.grpo_training_runs(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_grpo_model_registry_is_active ON public.grpo_model_registry(is_active);
CREATE INDEX IF NOT EXISTS idx_grpo_model_registry_model_name ON public.grpo_model_registry(model_name);
CREATE INDEX IF NOT EXISTS idx_grpo_model_registry_created_at ON public.grpo_model_registry(created_at DESC);

-- wordlists (wordlist management for Brutus and other credential tools)
CREATE TABLE IF NOT EXISTS public.wordlists (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    path        text NOT NULL,
    source      text DEFAULT 'upload',
    list_type   text DEFAULT 'passwords',
    line_count  integer,
    size_bytes  bigint,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_wordlists_list_type ON public.wordlists(list_type);

-- ============================================================================
-- TRIGGERS (updated_at auto-touch)
-- ============================================================================

DO $$ BEGIN IF to_regclass('public.findings') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_findings_touch_updated ON public.findings;
  CREATE TRIGGER trg_findings_touch_updated BEFORE UPDATE ON public.findings FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.web_findings') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_web_findings_updated_at ON public.web_findings;
  CREATE TRIGGER trg_web_findings_updated_at BEFORE UPDATE ON public.web_findings FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.vulns') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_vulns_updated_at ON public.vulns;
  CREATE TRIGGER trg_vulns_updated_at BEFORE UPDATE ON public.vulns FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.scan_recommendations') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_scan_recommendations_updated_at ON public.scan_recommendations;
  CREATE TRIGGER trg_scan_recommendations_updated_at BEFORE UPDATE ON public.scan_recommendations FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.playwright_scans') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_playwright_scans_updated_at ON public.playwright_scans;
  CREATE TRIGGER trg_playwright_scans_updated_at BEFORE UPDATE ON public.playwright_scans FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.playwright_findings') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_playwright_findings_updated_at ON public.playwright_findings;
  CREATE TRIGGER trg_playwright_findings_updated_at BEFORE UPDATE ON public.playwright_findings FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.zap_sessions') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_zap_sessions_updated_at ON public.zap_sessions;
  CREATE TRIGGER trg_zap_sessions_updated_at BEFORE UPDATE ON public.zap_sessions FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.kb_service_overrides') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_kb_service_overrides_updated_at ON public.kb_service_overrides;
  CREATE TRIGGER trg_kb_service_overrides_updated_at BEFORE UPDATE ON public.kb_service_overrides FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.scan_tool_feedback') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_scan_tool_feedback_updated_at ON public.scan_tool_feedback;
  CREATE TRIGGER trg_scan_tool_feedback_updated_at BEFORE UPDATE ON public.scan_tool_feedback FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.attack_vectors') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_attack_vectors_updated_at ON public.attack_vectors;
  CREATE TRIGGER trg_attack_vectors_updated_at BEFORE UPDATE ON public.attack_vectors FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.agent_sessions') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_agent_sessions_updated_at ON public.agent_sessions;
  CREATE TRIGGER trg_agent_sessions_updated_at BEFORE UPDATE ON public.agent_sessions FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.pending_exploits') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_pending_exploits_updated_at ON public.pending_exploits;
  CREATE TRIGGER trg_pending_exploits_updated_at BEFORE UPDATE ON public.pending_exploits FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.webhooks') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_webhooks_updated_at ON public.webhooks;
  CREATE TRIGGER trg_webhooks_updated_at BEFORE UPDATE ON public.webhooks FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.remote_nodes') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_remote_nodes_updated_at ON public.remote_nodes;
  CREATE TRIGGER trg_remote_nodes_updated_at BEFORE UPDATE ON public.remote_nodes FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.node_scan_jobs') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_node_scan_jobs_updated_at ON public.node_scan_jobs;
  CREATE TRIGGER trg_node_scan_jobs_updated_at BEFORE UPDATE ON public.node_scan_jobs FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.ad_attack_results') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_ad_attack_results_updated_at ON public.ad_attack_results;
  CREATE TRIGGER trg_ad_attack_results_updated_at BEFORE UPDATE ON public.ad_attack_results FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.grpo_feedback') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_grpo_feedback_updated_at ON public.grpo_feedback;
  CREATE TRIGGER trg_grpo_feedback_updated_at BEFORE UPDATE ON public.grpo_feedback FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.grpo_training_runs') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_grpo_training_runs_updated_at ON public.grpo_training_runs;
  CREATE TRIGGER trg_grpo_training_runs_updated_at BEFORE UPDATE ON public.grpo_training_runs FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.grpo_model_registry') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_grpo_model_registry_updated_at ON public.grpo_model_registry;
  CREATE TRIGGER trg_grpo_model_registry_updated_at BEFORE UPDATE ON public.grpo_model_registry FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

DO $$ BEGIN IF to_regclass('public.prompt_configs') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_prompt_configs_updated_at ON public.prompt_configs;
  CREATE TRIGGER trg_prompt_configs_updated_at BEFORE UPDATE ON public.prompt_configs FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
END IF; END$$;

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Recent high-severity findings across all sources
CREATE OR REPLACE VIEW public.all_high_severity_findings AS
SELECT 'web' as source, id, asset_id, url as location, name as title, severity, evidence, created_at
FROM public.web_findings WHERE severity IN ('high', 'critical')
UNION ALL
SELECT 'vuln' as source, v.id, v.asset_id, host(a.ip)::text || ':' || p.port as location, v.script as title, v.severity, v.output as evidence, v.created_at
FROM public.vulns v JOIN public.ports p ON v.port_id = p.id JOIN public.assets a ON v.asset_id = a.id WHERE v.severity IN ('high', 'critical')
UNION ALL
SELECT 'playwright' as source, pf.id, pf.asset_id, pf.url as location, pf.title, pf.severity, pf.evidence, pf.created_at
FROM public.playwright_findings pf WHERE pf.severity IN ('high', 'critical')
ORDER BY created_at DESC;

-- Pending scan recommendations
CREATE OR REPLACE VIEW public.pending_scan_recommendations AS
SELECT sr.id, sr.ip, sr.service, sr.scanner, sr.action, sr.script, sr.template, sr.priority, sr.confidence, sr.created_at, a.hostname
FROM public.scan_recommendations sr LEFT JOIN public.assets a ON sr.asset_id = a.id
WHERE sr.status = 'pending' ORDER BY sr.priority DESC, sr.created_at ASC;

-- LLM model comparison
CREATE OR REPLACE VIEW public.llm_model_comparison AS
SELECT model_name, COUNT(*) AS total_requests,
  ROUND(AVG(latency_ms)::numeric, 1) AS avg_latency_ms,
  ROUND(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p50_latency_ms,
  ROUND(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms)::numeric, 1) AS p95_latency_ms,
  ROUND(AVG(total_tokens)::numeric, 0) AS avg_total_tokens,
  ROUND(AVG(prompt_tokens)::numeric, 0) AS avg_prompt_tokens,
  ROUND(AVG(completion_tokens)::numeric, 0) AS avg_completion_tokens,
  ROUND(SUM(CASE WHEN has_tool_calls THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(*), 0) * 100, 1) AS tool_call_rate_pct,
  ROUND(SUM(CASE WHEN is_error THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(*), 0) * 100, 1) AS error_rate_pct,
  COUNT(DISTINCT session_id) AS session_count
FROM public.llm_request_metrics GROUP BY model_name;

-- Pipeline performance
CREATE OR REPLACE VIEW public.pipeline_performance AS
SELECT 'jobs' AS metric_source, j.id::text AS entity_id, NULL::uuid AS session_id, j.type AS scan_type, j.status, j.started_at, j.finished_at, EXTRACT(EPOCH FROM (j.finished_at - j.started_at)) AS duration_seconds
FROM public.jobs j WHERE j.started_at IS NOT NULL
UNION ALL
SELECT 'tasks', t.id::text, NULL::uuid, t.type, t.status, t.started_at, t.finished_at, EXTRACT(EPOCH FROM (t.finished_at - t.started_at))
FROM public.tasks t WHERE t.started_at IS NOT NULL
UNION ALL
SELECT 'agent_sessions', a.id::text, a.id, 'pentest_session', a.status, a.created_at, a.end_time, EXTRACT(EPOCH FROM (a.end_time - a.created_at))
FROM public.agent_sessions a
UNION ALL
SELECT 'playwright_scans', ps.id::text, NULL::uuid, 'playwright', ps.status, ps.start_time, ps.end_time, EXTRACT(EPOCH FROM (ps.end_time - ps.start_time))
FROM public.playwright_scans ps WHERE ps.start_time IS NOT NULL
UNION ALL
SELECT 'session_scan_metrics', ssm.id::text, ssm.session_id, ssm.scan_type, ssm.status, ssm.started_at, ssm.completed_at, ssm.duration_seconds
FROM public.session_scan_metrics ssm
UNION ALL
SELECT 'exploit_results', er.id::text, pe.session_id, 'exploit', CASE WHEN er.success THEN 'completed' ELSE 'failed' END, er.executed_at, er.completed_at, er.execution_time_ms / 1000.0
FROM public.exploit_results er JOIN public.pending_exploits pe ON er.pending_exploit_id = pe.id WHERE er.executed_at IS NOT NULL;

-- Detected software inventory (aggregates versions from ports, web_findings, recon_findings)
CREATE OR REPLACE VIEW public.detected_software AS
-- Source 1: Nmap/Masscan service detection (ports table)
SELECT
    a.id AS asset_id,
    host(a.ip)::text AS ip,
    a.hostname,
    p.port,
    p.proto AS protocol,
    COALESCE(p.product, p.service) AS product,
    p.version,
    'nmap' AS source,
    'service_detection' AS detection_type,
    p.created_at AS first_seen,
    COALESCE(p.updated_at, p.created_at) AS last_seen
FROM public.ports p
JOIN public.assets a ON p.asset_id = a.id
WHERE COALESCE(p.is_open, true)
  AND (p.product IS NOT NULL OR p.service IS NOT NULL)
UNION ALL
-- Source 2: httpx web server detection (recon_findings)
SELECT
    a.id AS asset_id,
    COALESCE(host(a.ip)::text, rf.target) AS ip,
    COALESCE(a.hostname, rf.target) AS hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    rf.data->>'webserver' AS product,
    NULL::text AS version,
    'httpx' AS source,
    'web_server' AS detection_type,
    rf.created_at AS first_seen,
    rf.created_at AS last_seen
FROM public.recon_findings rf
LEFT JOIN public.assets a ON rf.asset_id = a.id
WHERE rf.source = 'httpx' AND rf.data->>'webserver' IS NOT NULL
UNION ALL
-- Source 3: httpx tech detection (recon_findings, unnested)
SELECT
    a.id AS asset_id,
    COALESCE(host(a.ip)::text, rf.target) AS ip,
    COALESCE(a.hostname, rf.target) AS hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    CASE
        WHEN tech.value LIKE '%:%' THEN split_part(tech.value, ':', 1)
        ELSE tech.value
    END::text AS product,
    CASE
        WHEN tech.value ~ ':\d+[\d.]*$' THEN substring(tech.value from ':(\d+[\d.]*)$')
        ELSE NULL
    END::text AS version,
    'httpx' AS source,
    'tech_detection' AS detection_type,
    rf.created_at AS first_seen,
    rf.created_at AS last_seen
FROM public.recon_findings rf
LEFT JOIN public.assets a ON rf.asset_id = a.id,
LATERAL jsonb_array_elements_text(rf.data->'tech') AS tech(value)
WHERE rf.source = 'httpx' AND rf.data->'tech' IS NOT NULL AND jsonb_typeof(rf.data->'tech') = 'array'
UNION ALL
-- Source 4: WhatWeb plugin/tech detection (recon_findings, unnested)
SELECT
    a.id AS asset_id,
    COALESCE(host(a.ip)::text, rf.target) AS ip,
    COALESCE(a.hostname, rf.target) AS hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    CASE
        WHEN tech.value LIKE '%/%' THEN split_part(tech.value, '/', 1)
        ELSE tech.value
    END AS product,
    CASE
        WHEN tech.value LIKE '%/%' THEN split_part(tech.value, '/', 2)
        ELSE NULL
    END AS version,
    'whatweb' AS source,
    'tech_detection' AS detection_type,
    rf.created_at AS first_seen,
    rf.created_at AS last_seen
FROM public.recon_findings rf
LEFT JOIN public.assets a ON rf.asset_id = a.id,
LATERAL jsonb_array_elements_text(rf.data->'tech') AS tech(value)
WHERE rf.source = 'whatweb' AND rf.data->'tech' IS NOT NULL AND jsonb_typeof(rf.data->'tech') = 'array'
UNION ALL
-- Source 5: WAF detection (recon_findings)
SELECT
    a.id AS asset_id,
    COALESCE(host(a.ip)::text, rf.target) AS ip,
    COALESCE(a.hostname, rf.target) AS hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    rf.data->>'waf' AS product,
    NULL::text AS version,
    'wafw00f' AS source,
    'waf_detection' AS detection_type,
    rf.created_at AS first_seen,
    rf.created_at AS last_seen
FROM public.recon_findings rf
LEFT JOIN public.assets a ON rf.asset_id = a.id
WHERE rf.source = 'wafw00f' AND rf.data->>'waf' IS NOT NULL
UNION ALL
-- Source 6: ZAP "Tech Detected" alerts (web_findings)
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    CASE
        WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 1)
        ELSE substring(wf.name from 'Tech Detected - (.+)')
    END AS product,
    CASE
        WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 2)
        ELSE NULL
    END AS version,
    'zap' AS source,
    'tech_detection' AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'zap' AND wf.name LIKE 'Tech Detected%'
UNION ALL
-- Source 7: ZAP Server header / X-Powered-By leaks (web_findings)
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    CASE
        WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 1)
        ELSE wf.evidence
    END AS product,
    CASE
        WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 2)
        ELSE NULL
    END AS version,
    'zap' AS source,
    CASE
        WHEN wf.name ILIKE '%server%' THEN 'server_header'
        WHEN wf.name ILIKE '%powered%' THEN 'x_powered_by'
        ELSE 'version_leak'
    END AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'zap'
  AND wf.evidence IS NOT NULL
  AND wf.evidence != ''
  AND (wf.name ILIKE '%server leak%' OR wf.name ILIKE '%x-powered%' OR wf.name ILIKE '%version info%')
UNION ALL
-- Source 8: Nuclei tech-detect templates (web_findings)
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    wf.name AS product,
    NULL::text AS version,
    'nuclei' AS source,
    'tech_detection' AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'nuclei'
  AND (wf.issue_type ILIKE '%tech%' OR wf.issue_type ILIKE '%detect%' OR wf.name ILIKE '%detect%')
UNION ALL
-- Source 9: Katana JS/CSS versioned libraries (?ver= parameter)
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    -- Extract filename stem: last path segment before .min.js/.js/.css
    regexp_replace(
        substring(wf.url from '/([^/?]+)\.(min\.)?[jc]ss?(\?|$)'),
        '[-.](\d+[\d.]*\d)$', '', 'g'
    ) AS product,
    -- Extract version from ?ver= parameter
    substring(wf.url from '[?&]ver?=([0-9][0-9.]+)') AS version,
    'katana' AS source,
    'js_library' AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'katana'
  AND wf.url ~ '\.(js|css)(\?|$)'
  AND wf.url ~ '[?&]ver?=[0-9]'
UNION ALL
-- Source 10: Katana JS/CSS versioned filenames (name-1.2.3.js pattern)
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    -- Extract library name (everything before the version in the filename)
    regexp_replace(
        substring(wf.url from '/([^/]+)\.(min\.)?[jc]ss?(\?|$)'),
        '[-._](\d+\.)+\d+.*$', ''
    ) AS product,
    -- Extract version from filename (1.2.3 pattern)
    substring(wf.url from '/[^/]*?[-._](\d+\.\d+[\d.]*)\.(min\.)?[jc]ss?') AS version,
    'katana' AS source,
    'js_library' AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'katana'
  AND wf.url ~ '\.(js|css)(\?|$)'
  AND wf.url ~ '/[^/]*[-._]\d+\.\d+[^/]*\.(min\.)?[jc]ss?'
  AND NOT wf.url ~ '[?&]ver?=[0-9]'
UNION ALL
-- Source 11: Playwright security headers (Server, X-Powered-By leaks)
SELECT
    da.asset_id,
    COALESCE(host(a.ip)::text, substring(da.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    CASE
        WHEN hdr.key = 'server' THEN
            CASE WHEN hdr.value LIKE '%/%' THEN split_part(hdr.value, '/', 1) ELSE hdr.value END
        WHEN hdr.key = 'x-powered-by' THEN
            CASE WHEN hdr.value LIKE '%/%' THEN split_part(hdr.value, '/', 1) ELSE hdr.value END
        ELSE hdr.value
    END AS product,
    CASE
        WHEN hdr.value LIKE '%/%' THEN split_part(hdr.value, '/', 2)
        ELSE NULL
    END AS version,
    'playwright' AS source,
    CASE
        WHEN hdr.key = 'server' THEN 'server_header'
        WHEN hdr.key = 'x-powered-by' THEN 'x_powered_by'
        ELSE 'header_leak'
    END AS detection_type,
    da.created_at AS first_seen,
    da.created_at AS last_seen
FROM public.dom_analysis da
LEFT JOIN public.assets a ON da.asset_id = a.id,
LATERAL jsonb_each_text(da.security_headers) AS hdr(key, value)
WHERE hdr.key IN ('server', 'x-powered-by', 'x-aspnet-version', 'x-generator')
  AND hdr.value IS NOT NULL AND hdr.value != ''
UNION ALL
-- Source 12: Content extractions tech_indicators (generator meta, CMS, frameworks)
SELECT
    ce.asset_id,
    COALESCE(host(a.ip)::text, substring(ce.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    CASE
        WHEN ti->>'value' LIKE '%/%' THEN split_part(ti->>'value', '/', 1)
        WHEN ti->>'value' LIKE '% %' THEN split_part(ti->>'value', ' ', 1)
        ELSE ti->>'value'
    END AS product,
    CASE
        WHEN ti->>'value' ~ '\d+\.\d+' THEN
            substring(ti->>'value' from '(\d+\.\d+[\d.]*)')
        ELSE NULL
    END AS version,
    'playwright' AS source,
    CASE
        WHEN ti->>'type' = 'generator' THEN 'meta_generator'
        WHEN ti->>'type' IN ('wordpress','drupal','joomla') THEN 'cms_detection'
        WHEN ti->>'type' = 'x-powered-by' THEN 'x_powered_by'
        WHEN ti->>'type' = 'js_framework' THEN 'js_framework'
        ELSE 'tech_detection'
    END AS detection_type,
    ce.created_at AS first_seen,
    ce.created_at AS last_seen
FROM public.content_extractions ce
LEFT JOIN public.assets a ON ce.asset_id = a.id,
LATERAL jsonb_array_elements(ce.tech_indicators) AS ti
WHERE jsonb_typeof(ce.tech_indicators) = 'array'
  AND jsonb_array_length(ce.tech_indicators) > 0
  AND ti->>'value' IS NOT NULL AND ti->>'value' != ''
UNION ALL
-- Source 13: Playwright DOM javascript_libs (client-side library detection)
SELECT
    da.asset_id,
    COALESCE(host(a.ip)::text, substring(da.url from '://([^/:]+)')) AS ip,
    a.hostname,
    NULL::integer AS port,
    NULL::text AS protocol,
    lib->>'name' AS product,
    CASE
        WHEN lib->>'version' IN ('detected', 'detected in DOM') THEN NULL
        ELSE lib->>'version'
    END AS version,
    'playwright' AS source,
    'js_library' AS detection_type,
    da.created_at AS first_seen,
    da.created_at AS last_seen
FROM public.dom_analysis da
LEFT JOIN public.assets a ON da.asset_id = a.id,
LATERAL jsonb_array_elements(da.javascript_libs) AS lib
WHERE jsonb_typeof(da.javascript_libs) = 'array'
  AND jsonb_array_length(da.javascript_libs) > 0
  AND lib->>'name' IS NOT NULL AND lib->>'name' != ''
UNION ALL
-- Source 14: Web findings refs.technologies (GoWitness, httpx tech stored in web_findings)
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    COALESCE(a.hostname, substring(wf.url from '://([^/:]+)')) AS hostname,
    wf.port,
    NULL::text AS protocol,
    CASE
        WHEN tech.value LIKE '%:%' THEN split_part(tech.value, ':', 1)
        ELSE tech.value
    END AS product,
    CASE
        WHEN tech.value ~ ':\d+[\d.]*$' THEN substring(tech.value from ':(\d+[\d.]*)$')
        ELSE NULL
    END AS version,
    wf.source,
    'tech_detection' AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id,
LATERAL jsonb_array_elements_text(wf.refs->'technologies') AS tech(value)
WHERE wf.refs->'technologies' IS NOT NULL
  AND jsonb_typeof(wf.refs->'technologies') = 'array'
  AND jsonb_array_length(wf.refs->'technologies') > 0
UNION ALL
-- Source 15: Atlassian/Confluence version from static asset URLs
SELECT
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')) AS ip,
    COALESCE(a.hostname, substring(wf.url from '://([^/:]+)')) AS hostname,
    wf.port,
    NULL::text AS protocol,
    'Atlassian Confluence' AS product,
    substring(wf.url from '/(\d+\.\d+\.\d+)/_/download/') AS version,
    wf.source,
    'url_version' AS detection_type,
    wf.first_seen,
    wf.last_seen
FROM public.web_findings wf
LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.url ~ '/\d+\.\d+\.\d+/_/download/'
  AND substring(wf.url from '/(\d+\.\d+\.\d+)/_/download/') IS NOT NULL;

-- ============================================================================
-- software_research_cache (persists AI exploit research results per product+version)
CREATE TABLE IF NOT EXISTS public.software_research_cache (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    product     text NOT NULL,
    version     text NOT NULL DEFAULT '',
    source      text NOT NULL DEFAULT 'combined',
    results     jsonb NOT NULL DEFAULT '{}',
    cve_ids     text[] DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ix_sw_research_product_version ON public.software_research_cache(LOWER(product), LOWER(version), source);
CREATE INDEX IF NOT EXISTS ix_sw_research_updated ON public.software_research_cache(updated_at DESC);

-- TIER 6: Application settings (key-value store for API keys, config, etc.)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.app_settings (
    key        text PRIMARY KEY,
    value      text NOT NULL DEFAULT '',
    category   text NOT NULL DEFAULT 'general',
    updated_at timestamptz NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_app_settings_updated ON public.app_settings;
CREATE TRIGGER trg_app_settings_updated
  BEFORE UPDATE ON public.app_settings
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ============================================================================
-- TIER 7: Engagements & Workflow (pentest lifecycle)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.engagements (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                text NOT NULL,
    client              text,
    engagement_type     text DEFAULT 'external_pentest'
      CHECK (engagement_type IN ('external_pentest','internal_pentest','web_app','red_team','purple_team','phishing','other')),
    methodology         text DEFAULT 'custom',
    status              text DEFAULT 'planning'
      CHECK (status IN ('planning','active','paused','reporting','complete','archived')),
    start_date          date,
    end_date            date,
    scope_name          text,
    rules_of_engagement text,
    notes               text DEFAULT '',
    metadata            jsonb DEFAULT '{}',
    created_at          timestamptz DEFAULT now(),
    updated_at          timestamptz DEFAULT now()
);
ALTER TABLE public.engagements ADD COLUMN IF NOT EXISTS notes text DEFAULT '';

DROP TRIGGER IF EXISTS trg_engagements_updated ON public.engagements;
CREATE TRIGGER trg_engagements_updated
  BEFORE UPDATE ON public.engagements
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- Add nullable engagement_id FK to core tables (existing data stays NULL = unscoped)
ALTER TABLE public.findings           ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);
ALTER TABLE public.web_findings       ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);
ALTER TABLE public.vulns              ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);
ALTER TABLE public.recon_findings     ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);
ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);
ALTER TABLE public.assets             ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id);

-- Scan-execution tables: engagement_id for cross-engagement isolation.
-- ON DELETE SET NULL keeps scan history intact when an engagement is deleted
-- (the history loses its engagement context, but isn't destroyed).
-- NULL = legacy / unscoped — views must hide NULL rows when an engagement
-- is active (see dashboard/bff list_scans + audit-log filtering).
ALTER TABLE public.jobs                 ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.tasks                ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.scan_recommendations ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.pending_exploits     ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;
ALTER TABLE public.exploit_results      ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES public.engagements(id) ON DELETE SET NULL;

-- Partial indexes (engagement_id IS NOT NULL) for the dominant query
-- pattern: "show scans / tasks / recs / exploits for engagement X".
CREATE INDEX IF NOT EXISTS idx_jobs_engagement                  ON public.jobs(engagement_id)                 WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tasks_engagement                 ON public.tasks(engagement_id)                WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_engagement  ON public.scan_recommendations(engagement_id) WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pending_exploits_engagement      ON public.pending_exploits(engagement_id)     WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_results_engagement       ON public.exploit_results(engagement_id)      WHERE engagement_id IS NOT NULL;

-- Finding workflow columns (C1)
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS workflow_status text DEFAULT 'new'
    CHECK (workflow_status IN ('new','triaging','confirmed','false_positive','accepted_risk','in_report','deferred'));
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS assigned_to text;
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS verified_by text;
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS verified_at timestamptz;
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS tester_notes text;
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS original_severity text;
ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS report_ready boolean DEFAULT false;

ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS workflow_status text DEFAULT 'new'
    CHECK (workflow_status IN ('new','triaging','confirmed','false_positive','accepted_risk','in_report','deferred'));
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS assigned_to text;
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS verified_by text;
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS verified_at timestamptz;
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS tester_notes text;
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS original_severity text;
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS report_ready boolean DEFAULT false;

ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS workflow_status text DEFAULT 'new'
    CHECK (workflow_status IN ('new','triaging','confirmed','false_positive','accepted_risk','in_report','deferred'));
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS assigned_to text;
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS verified_by text;
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS verified_at timestamptz;
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS tester_notes text;
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS original_severity text;
ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS report_ready boolean DEFAULT false;

-- Finding activity / comments log (C2)
CREATE TABLE IF NOT EXISTS public.finding_activity (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_source text NOT NULL,
    finding_id     uuid NOT NULL,
    activity_type  text NOT NULL CHECK (activity_type IN ('comment','status_change','severity_change','assignment','evidence_added')),
    actor          text,
    old_value      text,
    new_value      text,
    comment        text,
    created_at     timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_activity_ref ON public.finding_activity(finding_source, finding_id);

-- Evidence store (B1)
CREATE TABLE IF NOT EXISTS public.evidence_store (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    evidence_type   text NOT NULL CHECK (evidence_type IN ('screenshot','request_response','terminal_output','file','note','video_clip')),
    title           text NOT NULL,
    description     text,
    content_type    text,
    content         bytea,
    content_text    text,
    thumbnail       bytea,
    file_size       integer,
    content_hash    text,
    tags            text[] DEFAULT '{}',
    uploaded_by     text,
    metadata        jsonb DEFAULT '{}',
    created_at      timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.evidence_links (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id    uuid NOT NULL REFERENCES public.evidence_store(id) ON DELETE CASCADE,
    entity_type    text NOT NULL CHECK (entity_type IN ('finding','web_finding','playwright_finding','asset','checklist_item','exploit_result')),
    entity_id      uuid NOT NULL,
    created_at     timestamptz DEFAULT now(),
    UNIQUE(evidence_id, entity_type, entity_id)
);

-- Campaign events / kill chain tracking (H1)
CREATE TABLE IF NOT EXISTS public.campaign_events (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    kill_chain_phase  text NOT NULL CHECK (kill_chain_phase IN (
        'reconnaissance','weaponization','delivery','exploitation',
        'installation','command_control','actions_on_objectives')),
    mitre_tactic      text,
    mitre_technique   text,
    title             text NOT NULL,
    description       text,
    target_asset_id   uuid,
    exploit_result_id uuid,
    node_id           uuid,
    timestamp         timestamptz NOT NULL DEFAULT now(),
    detected          boolean DEFAULT false,
    detection_time    timestamptz,
    operator          text,
    metadata          jsonb DEFAULT '{}',
    created_at        timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_campaign_events_engagement ON public.campaign_events(engagement_id);

-- Credential vault (H2)
CREATE TABLE IF NOT EXISTS public.credential_vault (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    username          text NOT NULL,
    domain            text,
    credential_type   text NOT NULL CHECK (credential_type IN (
        'password','ntlm_hash','krb_tgs','krb_tgt','ssh_key','api_token','certificate','other')),
    credential_value  text,
    cracked_value     text,
    source            text NOT NULL,
    source_entity_id  uuid,
    status            text DEFAULT 'active' CHECK (status IN ('active','cracking','cracked','expired','revoked')),
    access_level      text,
    grants_access_to  uuid[],
    notes             text,
    created_at        timestamptz DEFAULT now(),
    updated_at        timestamptz DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_credential_vault_updated ON public.credential_vault;
CREATE TRIGGER trg_credential_vault_updated
  BEFORE UPDATE ON public.credential_vault
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
-- Idempotency for vault-import-agent: same recon_finding can't produce two
-- credential rows. Partial index so manually-added creds (no source_entity_id)
-- don't collide.
CREATE UNIQUE INDEX IF NOT EXISTS ux_credvault_source_entity
    ON public.credential_vault(source, source_entity_id)
    WHERE source_entity_id IS NOT NULL;

-- ============================================================================
-- Identities — unified directory of detected user / SP / guest accounts.
-- Populated by parsers (microburst, azurehound, netexec, impacket, ...) via
-- upsert; one row per (provider, identifier). Links to credential_vault when
-- credentials for the same username/UPN are discovered.
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.identities (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider        text NOT NULL,                  -- 'azure', 'on_prem_ad', 'aws', 'gcp', etc.
    identifier      text NOT NULL,                  -- canonical: UPN (azure), sAM@domain (AD), ARN (aws)
    display_name    text,
    principal_type  text,                           -- 'user','guest','service_principal','group','computer'
    status          text DEFAULT 'unknown'
                    CHECK (status IN ('active','disabled','unknown','deleted')),
    mfa_state       text,                           -- 'enforced','enabled','disabled','unknown'
    last_signin     timestamptz,
    tenant_id       text,
    domain          text,
    is_admin        boolean DEFAULT false,
    is_guest        boolean DEFAULT false,
    is_dirsync      boolean DEFAULT false,
    tags            text[] DEFAULT '{}'::text[],
    sources         text[] NOT NULL DEFAULT '{}'::text[],
    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),
    raw             jsonb DEFAULT '{}'::jsonb,
    engagement_id   uuid REFERENCES public.engagements(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identities_provider_ident
    ON public.identities (provider, lower(identifier));
CREATE INDEX IF NOT EXISTS idx_identities_provider     ON public.identities(provider);
CREATE INDEX IF NOT EXISTS idx_identities_principal_type ON public.identities(principal_type);
CREATE INDEX IF NOT EXISTS idx_identities_engagement   ON public.identities(engagement_id);
CREATE INDEX IF NOT EXISTS idx_identities_admin        ON public.identities(is_admin) WHERE is_admin;
CREATE INDEX IF NOT EXISTS idx_identities_guest        ON public.identities(is_guest) WHERE is_guest;
CREATE INDEX IF NOT EXISTS idx_identities_last_seen    ON public.identities(last_seen DESC);

DROP TRIGGER IF EXISTS trg_identities_updated ON public.identities;
CREATE TRIGGER trg_identities_updated
  BEFORE UPDATE ON public.identities
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- Scheduled scans (I2)
CREATE TABLE IF NOT EXISTS public.scheduled_scans (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   uuid REFERENCES public.engagements(id),
    scan_type       text NOT NULL,
    targets         jsonb NOT NULL,
    parameters      jsonb DEFAULT '{}',
    scheduled_at    timestamptz NOT NULL,
    jitter_seconds  integer DEFAULT 0,
    max_rate        integer,
    status          text DEFAULT 'scheduled' CHECK (status IN ('scheduled','running','completed','cancelled','failed')),
    job_id          text,
    created_at      timestamptz DEFAULT now()
);

-- ============================================================================
-- TIER 8: Finding Tags + Screenshot Metadata
-- ============================================================================

ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS tags text[] DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_vulns_tags_gin ON public.vulns USING GIN (tags);

ALTER TABLE public.recon_findings ADD COLUMN IF NOT EXISTS tags text[] DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_recon_findings_tags_gin ON public.recon_findings USING GIN (tags);

ALTER TABLE public.playwright_findings ADD COLUMN IF NOT EXISTS tags text[] DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_playwright_findings_tags_gin ON public.playwright_findings USING GIN (tags);

-- web_findings.tags is jsonb (ZAP OWASP data) — add separate user_tags text[]
ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS user_tags text[] DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_web_findings_user_tags_gin ON public.web_findings USING GIN (user_tags);

CREATE TABLE IF NOT EXISTS public.screenshot_metadata (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    path        text UNIQUE NOT NULL,
    filename    text NOT NULL,
    directory   text,
    tags        text[] DEFAULT '{}',
    notes       text,
    added_to_scope text,
    created_at  timestamptz DEFAULT now(),
    updated_at  timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_screenshot_meta_tags ON public.screenshot_metadata USING GIN (tags);

DROP TRIGGER IF EXISTS trg_screenshot_metadata_updated ON public.screenshot_metadata;
CREATE TRIGGER trg_screenshot_metadata_updated
  BEFORE UPDATE ON public.screenshot_metadata
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ============================================================================
-- TIER 9: Follow-Up Tracking + OSINT Agent Feedback
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.follow_up_items (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_source text,
    finding_id     uuid,
    title          text NOT NULL,
    target         text,
    severity       text DEFAULT 'info',
    reason         text,
    status         text DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved','dismissed')),
    priority       text DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
    assigned_to    text,
    flagged_by     text DEFAULT 'manual',
    rule_id        text,
    confidence     float,
    tags           text[] DEFAULT '{}',
    notes          text,
    engagement_id  uuid,
    resolved_at    timestamptz,
    created_at     timestamptz DEFAULT now(),
    updated_at     timestamptz DEFAULT now(),
    metadata       jsonb DEFAULT '{}'
);
ALTER TABLE public.follow_up_items ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_followup_status     ON public.follow_up_items(status);
CREATE INDEX IF NOT EXISTS idx_followup_status_created ON public.follow_up_items(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_followup_nondismissed ON public.follow_up_items(created_at DESC) WHERE status != 'dismissed';
CREATE INDEX IF NOT EXISTS idx_followup_engagement ON public.follow_up_items(engagement_id);
CREATE INDEX IF NOT EXISTS idx_followup_finding    ON public.follow_up_items(finding_source, finding_id);
CREATE INDEX IF NOT EXISTS idx_followup_priority   ON public.follow_up_items(priority);
CREATE INDEX IF NOT EXISTS idx_followup_flagged_by ON public.follow_up_items(flagged_by);
CREATE UNIQUE INDEX IF NOT EXISTS ux_followup_title_target_rule ON public.follow_up_items(title, COALESCE(target, ''), COALESCE(rule_id, ''));

DROP TRIGGER IF EXISTS trg_followup_updated ON public.follow_up_items;
CREATE TRIGGER trg_followup_updated
  BEFORE UPDATE ON public.follow_up_items
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

CREATE TABLE IF NOT EXISTS public.osint_agent_feedback (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    follow_up_id     uuid REFERENCES follow_up_items(id) ON DELETE SET NULL,
    finding_context  jsonb NOT NULL,
    agent_suggestion text,
    agent_reasoning  text,
    agent_confidence float,
    user_action      text NOT NULL,
    user_notes       text,
    embedding        vector(384),
    created_at       timestamptz DEFAULT now()
);

-- IVFFlat index for RAG similarity — wrapped in DO block so it doesn't
-- fail if pgvector is unavailable or the table is still empty.
DO $$ BEGIN
  CREATE INDEX IF NOT EXISTS idx_feedback_embedding
      ON public.osint_agent_feedback USING ivfflat (embedding vector_l2_ops) WITH (lists = 50);
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'Could not create IVFFlat index on osint_agent_feedback: %', SQLERRM;
END $$;

-- ============================================================================
-- TIER 10: Detection Rule State (YAML rule engine)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.detection_rule_state (
    rule_id     text PRIMARY KEY,
    enabled     boolean NOT NULL DEFAULT true,
    source      text NOT NULL DEFAULT 'builtin',
    rule_yaml   text,
    created_at  timestamptz DEFAULT now(),
    updated_at  timestamptz DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_detection_rule_state_updated ON public.detection_rule_state;
CREATE TRIGGER trg_detection_rule_state_updated
  BEFORE UPDATE ON public.detection_rule_state
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ============================================================================
-- TIER 11: API Collections + Test Sessions (Swagger/OpenAPI Ingestion)
-- ============================================================================

-- API collection = one swagger file import
CREATE TABLE IF NOT EXISTS public.api_collections (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    base_url        text,
    openapi_version text,
    auth_type       text,           -- oauth2, apiKey, bearer, none
    auth_config     jsonb,          -- tokenUrl, scopes, etc from securitySchemes
    source_file     text,           -- original filename
    source_url      text,           -- original import URL (for re-auth)
    endpoint_count  int DEFAULT 0,
    created_at      timestamptz DEFAULT now(),
    updated_at      timestamptz DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_api_collections_updated ON public.api_collections;
CREATE TRIGGER trg_api_collections_updated
  BEFORE UPDATE ON public.api_collections
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- One row per method+path combination
CREATE TABLE IF NOT EXISTS public.api_endpoints (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   uuid NOT NULL REFERENCES api_collections(id) ON DELETE CASCADE,
    method          text NOT NULL,          -- GET, POST, PUT, DELETE, PATCH
    path            text NOT NULL,          -- /v1/appeals/{id}
    operation_id    text,
    summary         text,
    parameters      jsonb DEFAULT '[]',     -- [{name, in, required, type, description}]
    request_body    jsonb,                  -- {content_type, schema_name, required, fields: [{name, type, required}]}
    responses       jsonb DEFAULT '{}',     -- {200: {description}, 404: ...}
    security        jsonb,                  -- security requirements for this endpoint
    tags            text[],
    created_at      timestamptz DEFAULT now(),
    UNIQUE(collection_id, method, path)
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_collection ON public.api_endpoints(collection_id);

-- Test execution sessions
CREATE TABLE IF NOT EXISTS public.api_test_sessions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   uuid REFERENCES api_collections(id) ON DELETE SET NULL,
    name            text,
    jwt_token       text,
    proxy_url       text,           -- e.g., http://host.docker.internal:8080
    variables       jsonb DEFAULT '{}',  -- reusable vars like {envId: "abc123"}
    created_at      timestamptz DEFAULT now(),
    updated_at      timestamptz DEFAULT now()
);

DROP TRIGGER IF EXISTS trg_api_test_sessions_updated ON public.api_test_sessions;
CREATE TRIGGER trg_api_test_sessions_updated
  BEFORE UPDATE ON public.api_test_sessions
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- Individual test execution results
CREATE TABLE IF NOT EXISTS public.api_test_results (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      uuid REFERENCES api_test_sessions(id) ON DELETE CASCADE,
    endpoint_id     uuid REFERENCES api_endpoints(id) ON DELETE SET NULL,
    method          text NOT NULL,
    url             text NOT NULL,         -- fully resolved URL
    request_headers jsonb,
    request_body    text,
    status_code     int,
    response_headers jsonb,
    response_body   text,
    duration_ms     int,
    error           text,
    created_at      timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_test_results_session ON public.api_test_results(session_id);

-- Saved parameter configurations (reusable across test sessions)
CREATE TABLE IF NOT EXISTS public.api_param_configs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    collection_id   uuid REFERENCES api_collections(id) ON DELETE CASCADE,
    name            text NOT NULL,
    config          jsonb NOT NULL DEFAULT '{}',   -- {paramName: value, ...}
    auth_header     text,                          -- e.g. "Authorization: Bearer"
    created_at      timestamptz DEFAULT now(),
    updated_at      timestamptz DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_param_configs_collection ON public.api_param_configs(collection_id);

DROP TRIGGER IF EXISTS trg_api_param_configs_updated ON public.api_param_configs;
CREATE TRIGGER trg_api_param_configs_updated
  BEFORE UPDATE ON public.api_param_configs
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ============================================================================
-- PERMISSIONS
-- ============================================================================
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO app;

-- Also grant to scans role if it exists
DO $$ BEGIN
  GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scans;
  GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scans;
  GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO scans;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

-- ============================================================================
-- TIER 12: Finding Fingerprints (cross-tool dedup + delta)
-- ============================================================================

-- vulns: fingerprint = hash(asset_ip | port | script_base | first_cve | title_prefix)
-- This deduplicates e.g. nmap:smb-vuln-ms17-010 vs nessus:97833 when they share a CVE+port
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = 'public.vulns'::regclass AND attname = 'fingerprint'
  ) THEN
    ALTER TABLE public.vulns ADD COLUMN fingerprint text;
    CREATE INDEX idx_vulns_fingerprint ON public.vulns(fingerprint);
  END IF;
END$$;

-- web_findings: fingerprint = hash(url | source | name | issue_type)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = 'public.web_findings'::regclass AND attname = 'fingerprint'
  ) THEN
    ALTER TABLE public.web_findings ADD COLUMN fingerprint text;
    CREATE INDEX idx_web_findings_fingerprint ON public.web_findings(fingerprint);
  END IF;
END$$;

-- recon_findings: fingerprint = hash(source | finding_type | target | data_key)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = 'public.recon_findings'::regclass AND attname = 'fingerprint'
  ) THEN
    ALTER TABLE public.recon_findings ADD COLUMN fingerprint text;
    CREATE INDEX idx_recon_findings_fingerprint ON public.recon_findings(fingerprint);
  END IF;
END$$;

-- scan_runs: track individual scan executions for delta comparison
CREATE TABLE IF NOT EXISTS public.scan_runs (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tool        text NOT NULL,
    target      text,
    job_id      text,
    profile     text,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    finding_count integer DEFAULT 0,
    metadata    jsonb DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_tool ON public.scan_runs(tool);
CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON public.scan_runs(started_at DESC);

-- scan_run_findings: junction table linking runs to findings by fingerprint
CREATE TABLE IF NOT EXISTS public.scan_run_findings (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id      uuid NOT NULL REFERENCES public.scan_runs(id) ON DELETE CASCADE,
    finding_type text NOT NULL CHECK (finding_type IN ('vuln', 'web', 'recon')),
    finding_id  uuid NOT NULL,
    fingerprint text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_run_findings_run_id ON public.scan_run_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_scan_run_findings_fingerprint ON public.scan_run_findings(fingerprint);

-- ============================================================================
-- TIER 14: Cloud Credential & Token Management
-- ============================================================================

-- Expand credential_vault: add cloud credential types
ALTER TABLE public.credential_vault DROP CONSTRAINT IF EXISTS credential_vault_credential_type_check;
ALTER TABLE public.credential_vault ADD CONSTRAINT credential_vault_credential_type_check
  CHECK (credential_type IN ('password','ntlm_hash','krb_tgs','krb_tgt','ssh_key',
    'api_token','certificate','aws_access_key','aws_sts','azure_oauth','azure_sp','gcp_sa_key','other'));

-- Add cloud-specific columns
ALTER TABLE public.credential_vault ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE public.credential_vault ADD COLUMN IF NOT EXISTS cloud_metadata jsonb DEFAULT '{}';
ALTER TABLE public.credential_vault ADD COLUMN IF NOT EXISTS permissions_summary text;

-- Credential-to-resource access mapping
CREATE TABLE IF NOT EXISTS public.credential_access_map (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id   uuid NOT NULL REFERENCES public.credential_vault(id) ON DELETE CASCADE,
    resource_type   text NOT NULL,
    resource_id     text NOT NULL,
    access_level    text,
    verified        boolean DEFAULT false,
    verified_at     timestamptz,
    source          text,
    metadata        jsonb DEFAULT '{}',
    created_at      timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_credential_access_map_cred ON public.credential_access_map(credential_id);

-- Extend campaign_events kill_chain_phase for MITRE ATT&CK Cloud
ALTER TABLE public.campaign_events DROP CONSTRAINT IF EXISTS campaign_events_kill_chain_phase_check;
ALTER TABLE public.campaign_events ADD CONSTRAINT campaign_events_kill_chain_phase_check
  CHECK (kill_chain_phase IN (
    'reconnaissance','weaponization','delivery','exploitation',
    'installation','command_control','actions_on_objectives',
    'initial_access','persistence','privilege_escalation',
    'credential_access','discovery','collection','exfiltration'));

-- ============================================================================
-- TIER 15: Cloud Scan Recommendations (cloud suggestor)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_scan_recommendations (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         text NOT NULL,
    rule_name       text NOT NULL,
    priority        text NOT NULL CHECK (priority IN ('critical','high','medium','low')),
    tool            text NOT NULL,
    action          text NOT NULL,
    command_hint    text,
    import_as       text,
    trigger_source  text,
    trigger_finding_id uuid,
    trigger_summary text,
    provider        text,
    account_id      text,
    status          text DEFAULT 'open' CHECK (status IN ('open','accepted','dismissed','completed')),
    fingerprint     text UNIQUE,
    created_at      timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cloud_scan_recs_status ON public.cloud_scan_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_cloud_scan_recs_priority ON public.cloud_scan_recommendations(priority);
CREATE INDEX IF NOT EXISTS idx_cloud_scan_recs_provider ON public.cloud_scan_recommendations(provider);

-- AI triage columns: filled by cloud_triage_agent. triage_order is a small
-- integer (lower = do first); triage_reasoning is the LLM's one-line "why".
DO $$ BEGIN ALTER TABLE public.cloud_scan_recommendations ADD COLUMN IF NOT EXISTS triage_order integer; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.cloud_scan_recommendations ADD COLUMN IF NOT EXISTS triage_reasoning text; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.cloud_scan_recommendations ADD COLUMN IF NOT EXISTS triaged_at timestamptz; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_cloud_scan_recs_triage_order ON public.cloud_scan_recommendations(triage_order) WHERE triage_order IS NOT NULL;

-- One row per AI triage run. Keeps a history so you can compare ranking
-- shifts as new findings land. `top_actions` is a small list (~3) of
-- {rec_id, title, why} chosen by the LLM as the immediate next steps.
CREATE TABLE IF NOT EXISTS public.cloud_triage_runs (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    provider          text,
    open_recs_count   integer NOT NULL DEFAULT 0,
    top_actions       jsonb NOT NULL DEFAULT '[]'::jsonb,
    summary           text,
    model             text,
    prompt_tokens     integer,
    completion_tokens integer,
    latency_ms        integer,
    error             text,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cloud_triage_runs_engagement ON public.cloud_triage_runs(engagement_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cloud_triage_runs_provider   ON public.cloud_triage_runs(provider, created_at DESC);

-- ============================================================================
-- TIER 16: Sync Infrastructure (multi-node offline/online collaboration)
-- ============================================================================

-- sync_nodes: each machine/user that participates in sync
CREATE TABLE IF NOT EXISTS public.sync_nodes (
    node_id     text PRIMARY KEY,
    node_name   text NOT NULL,
    owner       text,
    created_at  timestamptz DEFAULT now(),
    last_sync   timestamptz,
    is_remote   boolean DEFAULT false
);

-- sync_state: per-node watermarks for last push/pull
CREATE TABLE IF NOT EXISTS public.sync_state (
    node_id         text NOT NULL REFERENCES sync_nodes(node_id),
    direction       text NOT NULL CHECK (direction IN ('push','pull')),
    last_lsn        bigint DEFAULT 0,
    last_sync_at    timestamptz DEFAULT now(),
    PRIMARY KEY (node_id, direction)
);

-- sync_log: append-only change log populated by triggers
-- Every INSERT/UPDATE/DELETE on tracked tables gets a row here
CREATE SEQUENCE IF NOT EXISTS sync_log_lsn_seq;
CREATE TABLE IF NOT EXISTS public.sync_log (
    lsn             bigint PRIMARY KEY DEFAULT nextval('sync_log_lsn_seq'),
    table_name      text NOT NULL,
    row_id          text NOT NULL,
    operation       text NOT NULL CHECK (operation IN ('INSERT','UPDATE','DELETE')),
    node_id         text DEFAULT 'local',
    changed_by      text,
    changed_at      timestamptz DEFAULT now(),
    row_data        jsonb,
    old_data        jsonb
);
CREATE INDEX IF NOT EXISTS idx_sync_log_table ON sync_log(table_name);
CREATE INDEX IF NOT EXISTS idx_sync_log_lsn ON sync_log(lsn);
CREATE INDEX IF NOT EXISTS idx_sync_log_changed_at ON sync_log(changed_at);
CREATE INDEX IF NOT EXISTS idx_sync_log_node ON sync_log(node_id);

-- sync_conflicts: records when push/pull detects conflicting changes
CREATE TABLE IF NOT EXISTS public.sync_conflicts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name      text NOT NULL,
    row_id          text NOT NULL,
    local_data      jsonb,
    remote_data     jsonb,
    local_changed_at  timestamptz,
    remote_changed_at timestamptz,
    resolution      text CHECK (resolution IN ('local_wins','remote_wins','manual','pending')),
    resolved_at     timestamptz,
    resolved_by     text,
    created_at      timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sync_conflicts_pending ON sync_conflicts(resolution) WHERE resolution = 'pending';

-- Add modified_by, modified_at, node_id to core finding tables
DO $$ BEGIN
    -- vulns
    ALTER TABLE vulns ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE vulns ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE vulns ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- web_findings
    ALTER TABLE web_findings ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE web_findings ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE web_findings ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- recon_findings
    ALTER TABLE recon_findings ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE recon_findings ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE recon_findings ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- assets
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE assets ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- ports
    ALTER TABLE ports ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE ports ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE ports ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- finding_activity
    ALTER TABLE finding_activity ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- evidence_store
    ALTER TABLE evidence_store ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- credential_vault
    ALTER TABLE credential_vault ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE credential_vault ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE credential_vault ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- campaign_events
    ALTER TABLE campaign_events ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
    -- engagements
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS modified_by text;
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS modified_at timestamptz DEFAULT now();
    ALTER TABLE engagements ADD COLUMN IF NOT EXISTS node_id text DEFAULT 'local';
END $$;

-- ── Sync trigger function ────────────────────────────────────────────
-- Captures every change to tracked tables into sync_log
CREATE OR REPLACE FUNCTION public._sync_log_trigger()
RETURNS trigger AS $$
DECLARE
    rid text;
    rdata jsonb;
    odata jsonb;
BEGIN
    IF TG_OP = 'DELETE' THEN
        rid := OLD.id::text;
        odata := to_jsonb(OLD);
        rdata := NULL;
    ELSIF TG_OP = 'INSERT' THEN
        rid := NEW.id::text;
        rdata := to_jsonb(NEW);
        odata := NULL;
    ELSE  -- UPDATE
        rid := NEW.id::text;
        rdata := to_jsonb(NEW);
        odata := to_jsonb(OLD);
    END IF;

    INSERT INTO sync_log (table_name, row_id, operation, node_id, changed_by, row_data, old_data)
    VALUES (
        TG_TABLE_NAME,
        rid,
        TG_OP,
        COALESCE(current_setting('app.node_id', true), 'local'),
        COALESCE(current_setting('app.user_id', true), 'system'),
        rdata,
        odata
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ── Attach triggers to tracked tables ────────────────────────────────
DO $$
DECLARE
    tbl text;
    tables text[] := ARRAY[
        'assets', 'ports', 'vulns', 'web_findings', 'recon_findings',
        'finding_activity', 'evidence_store', 'credential_vault',
        'campaign_events', 'engagements'
    ];
BEGIN
    FOREACH tbl IN ARRAY tables LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS trg_sync_log_%I ON %I', tbl, tbl
        );
        EXECUTE format(
            'CREATE TRIGGER trg_sync_log_%I
             AFTER INSERT OR UPDATE OR DELETE ON %I
             FOR EACH ROW EXECUTE FUNCTION _sync_log_trigger()',
            tbl, tbl
        );
    END LOOP;
END $$;

-- scope_targets (named scopes for grouping recon findings)
CREATE TABLE IF NOT EXISTS scope_targets (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL DEFAULT 'default',
    target      text NOT NULL,
    target_type text CHECK (target_type IN ('domain','ip','cidr','asn','url')),
    source      text,
    added_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE(name, target)
);
CREATE INDEX IF NOT EXISTS idx_scope_targets_name ON scope_targets(name);

-- ============================================================================
-- TIER 17: Scope Auto-Classification (learn from user scope decisions)
-- ============================================================================

CREATE TABLE IF NOT EXISTS scope_classification_rules (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    scope_name      text NOT NULL,
    priority        int NOT NULL DEFAULT 100,
    enabled         boolean NOT NULL DEFAULT true,
    rule_type       text NOT NULL CHECK (rule_type IN ('domain_pattern','whois_org','asn','tls_issuer','ip_cidr','composite')),
    conditions      jsonb NOT NULL,
    auto_apply      boolean NOT NULL DEFAULT false,
    created_at      timestamptz DEFAULT now(),
    updated_at      timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scope_decisions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target          text NOT NULL,
    target_type     text,
    from_scope      text NOT NULL,
    to_scope        text NOT NULL,
    context         jsonb NOT NULL DEFAULT '{}',
    context_text    text NOT NULL DEFAULT '',
    embedding       vector(384),
    decided_at      timestamptz DEFAULT now(),
    decided_by      text DEFAULT 'user'
);
CREATE INDEX IF NOT EXISTS idx_scope_decisions_to_scope ON scope_decisions(to_scope);
CREATE INDEX IF NOT EXISTS idx_scope_decisions_embedding ON scope_decisions USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50);

CREATE TABLE IF NOT EXISTS scope_suggestions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target          text NOT NULL UNIQUE,
    suggested_scope text NOT NULL,
    confidence      float NOT NULL,
    reasoning       text NOT NULL DEFAULT '',
    method          text NOT NULL CHECK (method IN ('rule','similarity','llm')),
    rule_id         uuid REFERENCES scope_classification_rules(id) ON DELETE SET NULL,
    similar_decisions uuid[],
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','rejected')),
    created_at      timestamptz DEFAULT now(),
    reviewed_at     timestamptz
);
CREATE INDEX IF NOT EXISTS idx_scope_suggestions_status ON scope_suggestions(status);

-- ============================================================================
-- ENGAGEMENT PROPAGATION TRIGGERS
-- Auto-inherit engagement_id from asset when inserting findings/follow-ups
-- ============================================================================

-- web_findings: inherit from asset_id or extract IP from URL
CREATE OR REPLACE FUNCTION propagate_engagement_to_web_findings()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.engagement_id IS NULL AND NEW.asset_id IS NOT NULL THEN
        SELECT engagement_id INTO NEW.engagement_id
        FROM assets WHERE id = NEW.asset_id;
    END IF;
    IF NEW.engagement_id IS NULL AND NEW.url IS NOT NULL THEN
        DECLARE _ip text;
        BEGIN
            _ip := substring(NEW.url from '://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})');
            IF _ip IS NOT NULL AND _ip ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' THEN
                BEGIN
                    SELECT engagement_id INTO NEW.engagement_id
                    FROM assets WHERE ip = _ip::inet LIMIT 1;
                EXCEPTION WHEN OTHERS THEN
                    NULL;
                END;
            END IF;
        END;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_web_findings_engagement ON web_findings;
CREATE TRIGGER trg_web_findings_engagement
    BEFORE INSERT ON web_findings FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_web_findings();

-- vulns: inherit from asset_id
CREATE OR REPLACE FUNCTION propagate_engagement_to_vulns()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.engagement_id IS NULL AND NEW.asset_id IS NOT NULL THEN
        SELECT engagement_id INTO NEW.engagement_id FROM assets WHERE id = NEW.asset_id;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_vulns_engagement ON vulns;
CREATE TRIGGER trg_vulns_engagement
    BEFORE INSERT ON vulns FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_vulns();

-- findings: inherit from asset_id
CREATE OR REPLACE FUNCTION propagate_engagement_to_findings()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.engagement_id IS NULL AND NEW.asset_id IS NOT NULL THEN
        SELECT engagement_id INTO NEW.engagement_id FROM assets WHERE id = NEW.asset_id;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_findings_engagement ON findings;
CREATE TRIGGER trg_findings_engagement
    BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_findings();

-- follow_up_items: extract IP from target, match to asset
CREATE OR REPLACE FUNCTION propagate_engagement_to_followups()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE _ip text;
BEGIN
    IF NEW.engagement_id IS NULL AND NEW.target IS NOT NULL THEN
        -- Extract IPv4 with strict 1-3 digit octets to avoid matching hex strings
        _ip := substring(NEW.target from '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})');
        IF _ip IS NOT NULL AND _ip ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' THEN
            BEGIN
                SELECT engagement_id INTO NEW.engagement_id
                FROM assets WHERE ip = _ip::inet LIMIT 1;
            EXCEPTION WHEN OTHERS THEN
                NULL;  -- skip if cast fails (not a valid IP)
            END;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_followups_engagement ON follow_up_items;
CREATE TRIGGER trg_followups_engagement
    BEFORE INSERT ON follow_up_items FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_followups();

-- recon_findings: inherit from asset_id (G3 — discovery findings should
-- carry their asset's engagement so they're scoped consistently with
-- web_findings/vulns; subfinder/dnsx also stamp it explicitly when in-scope).
CREATE OR REPLACE FUNCTION propagate_engagement_to_recon_findings()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.engagement_id IS NULL AND NEW.asset_id IS NOT NULL THEN
        SELECT engagement_id INTO NEW.engagement_id FROM assets WHERE id = NEW.asset_id;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_recon_findings_engagement ON recon_findings;
CREATE TRIGGER trg_recon_findings_engagement
    BEFORE INSERT ON recon_findings FOR EACH ROW EXECUTE FUNCTION propagate_engagement_to_recon_findings();

-- G3: hot lookup for the Recon Agent's engagement-scoped asset queries and
-- the discovery scope-gate stamping path.
CREATE INDEX IF NOT EXISTS idx_assets_engagement_ip ON public.assets(engagement_id, ip);

-- ============================================================================
-- ENGAGEMENT-SCOPED SCOPES (scope_targets belongs to an engagement)
-- ============================================================================

-- Step 1: Add engagement_id column (nullable for migration)
DO $$ BEGIN
  ALTER TABLE scope_targets ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES engagements(id) ON DELETE CASCADE;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
CREATE INDEX IF NOT EXISTS idx_scope_targets_engagement ON scope_targets(engagement_id);

-- Step 2: Migrate existing data — link scopes to engagements via scope_name
DO $$
DECLARE
  eng RECORD;
  legacy_id uuid;
BEGIN
  -- For each engagement with a scope_name, assign matching scope_targets
  FOR eng IN SELECT id, scope_name FROM engagements WHERE scope_name IS NOT NULL AND scope_name != '' LOOP
    UPDATE scope_targets SET engagement_id = eng.id
    WHERE name = eng.scope_name AND engagement_id IS NULL;
  END LOOP;

  -- Create "Legacy Scopes" engagement for orphaned scope_targets
  IF EXISTS (SELECT 1 FROM scope_targets WHERE engagement_id IS NULL LIMIT 1) THEN
    SELECT id INTO legacy_id FROM engagements WHERE name = 'Legacy Scopes' LIMIT 1;
    IF legacy_id IS NULL THEN
      INSERT INTO engagements (name, client, status, notes)
      VALUES ('Legacy Scopes', 'Migration', 'archived', 'Auto-created for scopes not linked to any engagement')
      RETURNING id INTO legacy_id;
    END IF;
    UPDATE scope_targets SET engagement_id = legacy_id WHERE engagement_id IS NULL;
  END IF;
END $$;

-- Step 3: New unique index (engagement_id, name, target) — allows same scope name in different engagements
CREATE UNIQUE INDEX IF NOT EXISTS ux_scope_targets_eng_name_target
  ON scope_targets(engagement_id, name, target);

-- Step 3b: Drop the legacy table-level UNIQUE(name, target) constraint that
-- blocked the same target from existing in another engagement's scope.
-- Postgres auto-names this constraint scope_targets_name_target_key.
DO $$ BEGIN
  ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS scope_targets_name_target_key;
EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- Step 4: Add engagement_id to scope classification tables
DO $$ BEGIN ALTER TABLE scope_classification_rules ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES engagements(id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE scope_decisions ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES engagements(id); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE scope_suggestions ADD COLUMN IF NOT EXISTS engagement_id uuid REFERENCES engagements(id); EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- ============================================================================
-- TIER 18: Scan Pipelines (multi-stage parallel orchestration)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.scan_pipelines (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    name            text NOT NULL DEFAULT 'default',
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','completed','failed','stopped')),
    profile         text NOT NULL DEFAULT 'pentest',
    config          jsonb NOT NULL DEFAULT '{}',
    targets         jsonb NOT NULL DEFAULT '[]',
    target_count    int NOT NULL DEFAULT 0,
    progress        jsonb NOT NULL DEFAULT '{}',
    host_states     jsonb NOT NULL DEFAULT '{}',
    jobs_spawned    int NOT NULL DEFAULT 0,
    jobs_completed  int NOT NULL DEFAULT 0,
    jobs_failed     int NOT NULL DEFAULT 0,
    findings_count  int NOT NULL DEFAULT 0,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz
);

CREATE INDEX IF NOT EXISTS idx_scan_pipelines_engagement ON scan_pipelines(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scan_pipelines_status ON scan_pipelines(status);

-- scan_pipeline_jobs: tracks every job spawned by a pipeline
CREATE TABLE IF NOT EXISTS public.scan_pipeline_jobs (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id   uuid NOT NULL REFERENCES public.scan_pipelines(id) ON DELETE CASCADE,
    job_id        text NOT NULL,
    host          text,
    stage         int NOT NULL DEFAULT 0,
    scan_type     text NOT NULL,
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','running','completed','failed','stopped')),
    result        jsonb,
    created_at    timestamptz NOT NULL DEFAULT now(),
    completed_at  timestamptz
);

CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_pipeline ON scan_pipeline_jobs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_job_id ON scan_pipeline_jobs(job_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_host ON scan_pipeline_jobs(host);
CREATE UNIQUE INDEX IF NOT EXISTS ux_pipeline_jobs_pipeline_job ON scan_pipeline_jobs(pipeline_id, job_id);

-- ============================================================================
-- TIER 19: Autonomous Recon Agent
-- ============================================================================

-- Per-engagement agent config + runtime state
CREATE TABLE IF NOT EXISTS public.recon_agent_state (
    engagement_id   uuid PRIMARY KEY REFERENCES public.engagements(id) ON DELETE CASCADE,
    enabled         boolean NOT NULL DEFAULT false,
    interval_sec    integer NOT NULL DEFAULT 300,
    last_run_at     timestamptz,
    last_scan_at    timestamptz,
    last_dispatch_at timestamptz,
    pause_until     timestamptz,
    config          jsonb NOT NULL DEFAULT '{}',
    stats           jsonb NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Tracks what has been scanned per target per stage
CREATE TABLE IF NOT EXISTS public.scope_coverage (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id   uuid NOT NULL REFERENCES public.engagements(id) ON DELETE CASCADE,
    target          text NOT NULL,
    stage           integer NOT NULL DEFAULT 0,
    stage_name      text,
    scan_type       text,
    job_id          text,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','running','completed','failed','skipped')),
    started_at      timestamptz,
    completed_at    timestamptz,
    UNIQUE(engagement_id, target, stage, scan_type)
);

CREATE INDEX IF NOT EXISTS idx_scope_cov_engagement ON scope_coverage(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scope_cov_status ON scope_coverage(status);
CREATE INDEX IF NOT EXISTS idx_scope_cov_target ON scope_coverage(engagement_id, target);

-- gap_analysis_reports — per-engagement recon gap analysis
CREATE TABLE IF NOT EXISTS public.gap_analysis_reports (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id    uuid NOT NULL REFERENCES public.engagements(id) ON DELETE CASCADE,
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    report           jsonb NOT NULL DEFAULT '{}',
    gaps_found       integer NOT NULL DEFAULT 0,
    scans_dispatched integer NOT NULL DEFAULT 0,
    recommendations  jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    triggered_by     text DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_gap_reports_engagement ON gap_analysis_reports(engagement_id);
CREATE INDEX IF NOT EXISTS idx_gap_reports_created ON gap_analysis_reports(created_at DESC);

-- ============================================================================
-- TIER 14: Burp Follow-Up Queue
-- Queue of follow-up findings destined for import into Burp Suite via
-- the RagScanBridge extension. Items carry enriched finding data so the
-- extension can render full request/response details.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.burp_followup_queue (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    follow_up_id    uuid REFERENCES follow_up_items(id) ON DELETE CASCADE,
    title           text NOT NULL,
    url             text,
    target          text,
    severity        text DEFAULT 'info',
    finding_source  text,
    finding_id      uuid,
    method          text DEFAULT 'GET',
    request_raw     text,
    response_raw    text,
    evidence        text,
    description     text,
    cves            text[],
    metadata        jsonb DEFAULT '{}',
    status          text DEFAULT 'pending' CHECK (status IN ('pending','imported','dismissed')),
    queued_at       timestamptz DEFAULT now(),
    imported_at     timestamptz
);

CREATE INDEX IF NOT EXISTS idx_burp_queue_status    ON public.burp_followup_queue(status);
CREATE INDEX IF NOT EXISTS idx_burp_queue_followup  ON public.burp_followup_queue(follow_up_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_burp_queue_followup ON public.burp_followup_queue(follow_up_id) WHERE status = 'pending';

-- ============================================================================
-- TIER 21: News Intelligence (security threat-news aggregator)
-- Per-source registry, per-vulnerability dedup'd news items with status pipeline
-- (NEW → Reviewed → Follow-up → Applies → Research → Future), and a local
-- mirror of the CISA KEV catalog so enrichment can flag without an outbound
-- call per item.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.news_sources (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL,
    url              text NOT NULL,
    parser           text NOT NULL DEFAULT 'rss' CHECK (parser IN ('rss','atom','html')),
    enabled          boolean NOT NULL DEFAULT true,
    last_fetched_at  timestamptz,
    last_status      text,           -- 'ok' | 'error' | 'rate_limited'
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_news_sources_url ON public.news_sources(url);

CREATE TABLE IF NOT EXISTS public.news_items (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint              text UNIQUE NOT NULL,
    title                    text NOT NULL,
    summary                  text,
    primary_cve              text,
    all_cves                 text[] NOT NULL DEFAULT '{}'::text[],
    status                   text NOT NULL DEFAULT 'new'
                             CHECK (status IN ('new','reviewed','follow_up','applies','research','future','deleted')),
    acknowledged_by          text,
    acknowledged_at          timestamptz,
    -- Enrichment flags. NULL = unknown (frontend renders as "UNKNOWN").
    kev_listed               boolean,
    rce                      boolean,
    easily_exploitable       boolean,
    malware_exploitable      boolean,
    active_internet_breach   boolean,
    patch_available          boolean,
    -- Aggregated jsonb arrays.
    articles                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    github_links             jsonb NOT NULL DEFAULT '[]'::jsonb,
    asset_matches            jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Timestamps.
    first_seen               timestamptz NOT NULL DEFAULT now(),
    last_seen                timestamptz NOT NULL DEFAULT now(),
    enriched_at              timestamptz,
    github_searched_at       timestamptz,
    asset_matched_at         timestamptz,
    -- Triage extras.
    notes                    text,
    tags                     text[] NOT NULL DEFAULT '{}'::text[],
    metadata                 jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_news_items_status_last_seen
    ON public.news_items(status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_news_items_primary_cve
    ON public.news_items(primary_cve) WHERE primary_cve IS NOT NULL AND primary_cve <> 'UNKNOWN';
CREATE INDEX IF NOT EXISTS idx_news_items_all_cves_gin
    ON public.news_items USING GIN(all_cves);
CREATE INDEX IF NOT EXISTS idx_news_items_kev
    ON public.news_items(kev_listed) WHERE kev_listed = true;

-- Default news sources seeded on fresh install.  ON CONFLICT (url) DO
-- NOTHING means existing installs aren't disturbed: only sources whose
-- URLs aren't already in the DB get inserted on subsequent runs.
INSERT INTO public.news_sources (name, url, parser, enabled)
VALUES
    -- Tier 1: major news outlets
    ('BleepingComputer',            'https://www.bleepingcomputer.com/feed/',                       'rss',  true),
    ('Krebs on Security',           'https://krebsonsecurity.com/feed/',                            'rss',  true),
    ('The Hacker News',             'https://feeds.feedburner.com/TheHackersNews',                  'rss',  true),
    ('Dark Reading',                'https://www.darkreading.com/rss.xml',                          'rss',  true),
    ('SecurityWeek',                'https://www.securityweek.com/feed/',                           'rss',  true),
    ('CyberScoop',                  'https://cyberscoop.com/feed/',                                 'rss',  true),
    ('CSO Online',                  'https://www.csoonline.com/index.rss',                          'rss',  true),
    ('Cybersecurity Dive',          'https://www.cybersecuritydive.com/feeds/news/',                'rss',  true),
    ('Help Net Security',           'https://www.helpnetsecurity.com/feed/',                        'rss',  true),
    ('TechCrunch Security',         'https://techcrunch.com/category/security/feed/',               'rss',  true),
    -- Tier 2: vendor / official advisories
    ('CISA Alerts',                 'https://www.cisa.gov/cybersecurity-advisories/all.xml',        'rss',  true),
    ('Microsoft MSRC',              'https://msrc.microsoft.com/blog/feed',                         'rss',  true),
    ('GitHub Security Advisories',  'https://github.com/advisories.atom',                           'atom', true),
    -- Tier 3: high-signal research / disclosures
    ('Google Project Zero',         'https://googleprojectzero.blogspot.com/feeds/posts/default',   'atom', true),
    ('PortSwigger Research',        'https://portswigger.net/research/rss',                         'rss',  true),
    ('Assetnote Research',          'https://www.assetnote.io/feed.xml',                            'rss',  true),
    ('watchTowr Labs',              'https://labs.watchtowr.com/rss/',                              'rss',  true)
ON CONFLICT (url) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.news_runs (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    triggered_by     text DEFAULT 'manual',         -- 'manual' | 'scheduler' | 'deep_search'
    status           text NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running','completed','failed')),
    started_at       timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    sources_fetched  integer NOT NULL DEFAULT 0,
    articles_seen    integer NOT NULL DEFAULT 0,
    items_new        integer NOT NULL DEFAULT 0,
    items_updated    integer NOT NULL DEFAULT 0,
    items_enriched   integer NOT NULL DEFAULT 0,
    error            text,
    per_source       jsonb NOT NULL DEFAULT '[]'::jsonb,
    topic            text                            -- only set for deep_search runs
);
CREATE INDEX IF NOT EXISTS idx_news_runs_started ON public.news_runs(started_at DESC);

CREATE TABLE IF NOT EXISTS public.cisa_kev_cache (
    cve_id              text PRIMARY KEY,
    date_added          date,
    short_description   text,
    required_action     text,
    known_ransomware    boolean DEFAULT false,
    fetched_at          timestamptz NOT NULL DEFAULT now()
);

-- ============================================================================
-- TIER 20: Cloud Tenant Discovery
-- Per-domain provider tenant identifiers + indicators discovered via passive
-- recon (Azure OpenID configuration, AWS DNS heuristics). One row per
-- (domain, provider) pair. Cross-references existing identities.tenant_id
-- and cloud_scan_recommendations.account_id where possible.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.cloud_tenants (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    domain            text NOT NULL,
    provider          text NOT NULL CHECK (provider IN ('azure', 'aws', 'gcp')),
    tenant_id         text,                 -- Azure tenant GUID; AWS account ID if leaked; null otherwise
    federation_type   text,                 -- Managed | Federated | Unknown (Azure)
    sts_auth_url      text,                 -- AdFS / federated IdP endpoint (Azure)
    name_space_type   text,                 -- 'Managed' / 'Federated' / 'Unknown' (Azure GetUserRealm)
    cloud_instance    text,                 -- e.g. 'microsoftonline.com' / 'microsoftonline.us'
    indicators        jsonb NOT NULL DEFAULT '{}'::jsonb,  -- DNS records, SES TXT, CNAMEs, raw responses
    engagement_id     uuid REFERENCES engagements(id) ON DELETE SET NULL,
    first_seen        timestamptz NOT NULL DEFAULT now(),
    last_seen         timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_cloud_tenants_domain_provider
    ON public.cloud_tenants(LOWER(domain), provider);
CREATE INDEX IF NOT EXISTS idx_cloud_tenants_tenant_id
    ON public.cloud_tenants(tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_cloud_tenants_engagement
    ON public.cloud_tenants(engagement_id) WHERE engagement_id IS NOT NULL;

-- ============================================================================
-- TIER 22: Chat Presets (saved operator prompts for the dashboard chat panel)
-- ============================================================================
-- Operators save common multi-step queries (e.g. "find AWS infra and pivot
-- to MicroBurst-discovered users") as named presets. Templates can include
-- {engagement} / {target} / {domain} placeholders that the BFF fills in
-- when the operator clicks the preset.
CREATE TABLE IF NOT EXISTS public.chat_presets (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    title             text NOT NULL,
    category          text,
    description       text,
    prompt_template   text NOT NULL,
    placeholders      text[] DEFAULT '{}'::text[],
    tags              text[] DEFAULT '{}'::text[],
    created_by        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_used_at      timestamptz,
    use_count         integer NOT NULL DEFAULT 0,
    UNIQUE (engagement_id, title)
);
CREATE INDEX IF NOT EXISTS idx_chat_presets_engagement ON public.chat_presets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_chat_presets_category   ON public.chat_presets(category);
CREATE INDEX IF NOT EXISTS idx_chat_presets_last_used  ON public.chat_presets(last_used_at DESC NULLS LAST);

-- allowed_tools: per-preset tool catalog allowlist (NULL = no restriction).
-- When set, the chat backend filters the model's tool list to only these
-- entries AND the dispatcher refuses any call to a tool outside the list,
-- returning a structured error the model can read and adapt to. This is
-- layers 2+3 of the LLM-hardening stack (see Docs/CHANGES_MADE.md).
DO $$ BEGIN
    ALTER TABLE public.chat_presets
        ADD COLUMN IF NOT EXISTS allowed_tools text[] DEFAULT NULL;
EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- Seed the AWS → MicroBurst pivot preset as a starting example. Operators
-- can edit / delete it. Idempotent via ON CONFLICT.
-- Engagement_id NULL = global preset (visible across all engagements).
INSERT INTO public.chat_presets (engagement_id, title, category, description, prompt_template, placeholders, tags, created_by)
SELECT NULL,
       'AWS infra → MicroBurst user pivot',
       'cloud',
       'Find AWS-hosted apps in scope, identify owning tenant, then pull MicroBurst-discovered identities for password-spray candidates.',
       $$You are running a non-interactive multi-step workflow. The operator is NOT here to answer questions. They will read your final report only after STEP 4 is complete. Until then, keep calling tools and emitting step output.

ABSOLUTE RULES:
- DO NOT ask the operator anything.
- DO NOT say "let me know if", "would you like", "if you want", "for example", "could you provide", or any phrase that defers to the operator.
- DO NOT summarize one tool result and stop.
- The output you produce IS the deliverable.

ANTI-HALLUCINATION:
- The ONLY domains, hostnames, tenants, and accounts you may name are those that appear in tool RESULTS in this session. Never invent.
- The strings example.com, example.org, target.invalid, foo.com, test.com are FORBIDDEN.

ENUMERATION RULES:
- When a tool returns N rows, your output MUST contain N entries. Do NOT sample.

CRITICAL — TOOL CHOICE: This workflow ONLY queries existing data. The ONLY tools you may call are: get_assets, search_recon, search_findings, search_identities. (start_* calls are refused by the backend.)

GOAL: produce a list of REAL USER ACCOUNTS (UPNs / emails) that the operator can use for password-spray / SSO testing against the AWS-hosted apps in scope. NOT groups. NOT applications. USERS — entries with a `UserPrincipalName` field.

DATA-MODEL FACTS — read carefully, this is the #1 source of mistakes:
- MicroBurst Azure-AD data lives in `recon_findings` rows with `source='microburst'`. It is NOT in the identities table.
- search_identities queries the identities table — for MicroBurst data, this RETURNS NOTHING. Use search_findings with source="microburst" instead.
- search_findings WITHOUT a source filter returns web vulns / DAST findings / etc. — the wrong dataset. Always include source="microburst" when looking for users.
- Three relevant finding_type values inside source=microburst:
    azure_user         → data.row.UserPrincipalName        (a user; list it)
    azure_group_member → data.row.UserPrincipalName        (the user); data.row.`Group Name` (context)
    azure_group        → data.row.DisplayName              (a group; signal only — do NOT list)

SCOPE: every result must come from data tagged to engagement {engagement}.

TOOL CALL FORMAT — exact name, no prefixes.
  CORRECT: get_assets({"provider": "aws", "limit": 5000})
  WRONG:   query:get_assets, tools.get_assets, functions.get_assets

EXECUTE NOW.

============================================================
STEP 1 — AWS surface area
============================================================
Call get_assets({"provider": "aws", "limit": 5000}).

If 0 rows, fallback in sequence:
  get_assets({"search":"amazonaws", "limit":5000})
  get_assets({"search":"cloudfront", "limit":5000})

OUTPUT: one bullet per UNIQUE hostname returned. Each: "<hostname> — provider_evidence: <evidence>".

Then "DERIVED APP NAMES (deduplicated):" — for each hostname, the BRAND/APP NAME = the leftmost label of the REGISTRABLE DOMAIN (NOT the leftmost label of the full hostname). Strip subdomain prefixes. Examples:
  content.widgets.com   → registrable = widgets.com    → app: "widgets"
  pay.acme.com          → registrable = acme.com       → app: "acme"
  host.nxt.acme.com     → registrable = acme.com       → app: "acme"   (NOT "nxt.acme")
  app123.svc.acme.com   → registrable = acme.com       → app: "acme"   (NOT "svc.acme")
DEDUPLICATE the app-name list — if 17 hostnames map to "acme", the unique list has 1 entry "acme", not 17. You will run STEP 3 PASS B once per UNIQUE app name.

============================================================
STEP 2 — Application identity
============================================================
For EACH hostname from step 1, call all three:
  search_recon({"source":"crtsh","target":"<hostname>"})
  search_recon({"source":"whatweb","target":"<hostname>"})
  search_findings({"source":"microburst","search":"<hostname>","limit":5000})
Bullet each (hostname → tenant_or_org). If unknown, "(no tenant found)".

============================================================
STEP 3 — Pivot to USERS associated with each app
============================================================
TWO passes. Run both — they catch different data.

PASS A — by tenant (only when STEP 2 found one). For each distinct tenant:
  search_identities({"provider":"microburst","search":"<tenant_or_domain>","limit":5000})
NOTE: if PASS A returns 0, that's expected — the identities table may not have MicroBurst data. PASS B is what actually finds users.

PASS B — by APP NAME (MANDATORY, run for EACH UNIQUE app name from step 1):
  search_findings({"source":"microburst","search":"<app_name>","limit":5000})
  ☆ source="microburst" is REQUIRED. Without it you get web vulns instead of users. ☆

PROCESS the search_findings result (each row has finding_type and data):
  - Skip rows where finding_type = 'azure_group' — those are groups, not users.
  - For rows where finding_type = 'azure_user': extract data.row.UserPrincipalName → user.
  - For rows where finding_type = 'azure_group_member': extract data.row.UserPrincipalName → user. Also note data.row.`Group Name` as context (e.g. "AAD-ServiceAccounts", "Domain Admins").
  - Deduplicate users by UserPrincipalName.

OUTPUT: bullet each unique UPN, grouped by app. Format:
  <UserPrincipalName>  (groups: <Group A>, <Group B>; via PASS B/app=<app>)
If 0 users across both passes for an app, write "STEP 3: 0 user accounts for app=<app_name>".

If search_findings returns rows where finding_type is NOT one of azure_user / azure_group_member / azure_group — IGNORE them. They are unrelated data sources (web findings, vulns, etc.) that happened to match the search string. The source="microburst" filter should already eliminate them, but stay strict.

============================================================
STEP 4 — FINAL TABLE
============================================================
Markdown table — one row per unique UserPrincipalName from step 3:

| UserPrincipalName | groups (sample, max 3) | suggested AWS app to spray (hostname — provider_evidence) |
| ----------------- | ---------------------- | --------------------------------------------------------- |

Match users to AWS apps by APP NAME. If a user surfaced via app="acme", pair them with ALL *.acme.com hostnames from step 1 (or pick the most relevant: sso.*, login.*, app.*, admin.* in that priority order).

Then ONE summary line:
  Total users: N. Distinct groups: G. AWS apps reachable: H (= count from step 1).

That is the end of your response. Do not add commentary, suggestions, or questions. Begin STEP 1 now.$$,
       ARRAY['engagement']::text[],
       ARRAY['cloud', 'aws', 'identity', 'microburst', 'pivot']::text[],
       'system'
WHERE NOT EXISTS (
    SELECT 1 FROM public.chat_presets
    WHERE engagement_id IS NULL AND title = 'AWS infra → MicroBurst user pivot'
);

-- Azure → MicroBurst user pivot preset (mirrors AWS preset structure).
INSERT INTO public.chat_presets
  (engagement_id, title, category, description, prompt_template,
   placeholders, tags, allowed_tools, created_by)
SELECT NULL,
       'Azure infra → MicroBurst user pivot',
       'cloud',
       'Find Azure-hosted apps in scope, identify owning tenant, then pull MicroBurst-discovered users from azure_group_member rows for password-spray candidates.',
       $$You are running a non-interactive multi-step workflow. The operator is NOT here to answer questions. They will read your final report only after STEP 4 is complete. Until then, keep calling tools and emitting step output.

ABSOLUTE RULES:
- DO NOT ask the operator anything.
- DO NOT say "let me know if", "would you like", "if you want", "for example", "could you provide", or any phrase that defers to the operator.
- DO NOT summarize one tool result and stop.
- The output you produce IS the deliverable.

ANTI-HALLUCINATION:
- The ONLY domains, hostnames, tenants, and accounts you may name are those that appear in tool RESULTS in this session. Never invent.
- The strings example.com, example.org, target.invalid, foo.com, test.com are FORBIDDEN.

ENUMERATION RULES:
- When a tool returns N rows, your output MUST contain N entries. Do NOT sample.

CRITICAL — TOOL CHOICE: This workflow ONLY queries existing data. The ONLY tools you may call are: get_assets, search_recon, search_findings, search_identities. (start_* calls are refused by the backend.)

GOAL: produce a list of REAL USER ACCOUNTS (UPNs / emails) that the operator can use for password-spray / SSO testing against the Azure-hosted apps in scope. NOT groups. NOT applications. USERS — entries with a `UserPrincipalName` field.

DATA-MODEL FACTS — read carefully, this is the #1 source of mistakes:
- MicroBurst Azure-AD data lives in `recon_findings` rows with `source='microburst'`. It is NOT in the identities table.
- search_identities queries the identities table — for MicroBurst data, this RETURNS NOTHING. Use search_findings with source="microburst" instead.
- search_findings WITHOUT a source filter returns web vulns / DAST findings / etc. — the wrong dataset. Always include source="microburst" when looking for users.
- Three relevant finding_type values inside source=microburst:
    azure_user         → data.row.UserPrincipalName        (a user; list it)
    azure_group_member → data.row.UserPrincipalName        (the user); data.row.`Group Name` (context)
    azure_group        → data.row.DisplayName              (a group; signal only — do NOT list)

SCOPE: every result must come from data tagged to engagement {engagement}.

TOOL CALL FORMAT — exact name, no prefixes.
  CORRECT: get_assets({"provider": "azure", "limit": 5000})
  WRONG:   query:get_assets, tools.get_assets, functions.get_assets

EXECUTE NOW.

============================================================
STEP 1 — Azure surface area
============================================================
Call get_assets({"provider": "azure", "limit": 5000}).

If 0 rows, fallback in sequence:
  get_assets({"search":"azurewebsites", "limit":5000})
  get_assets({"search":"cloudapp.net", "limit":5000})
  get_assets({"search":"trafficmanager", "limit":5000})

OUTPUT: one bullet per UNIQUE hostname returned. Each: "<hostname> — provider_evidence: <evidence>".

Then "DERIVED APP NAMES (deduplicated):" — for each hostname, the BRAND/APP NAME = the leftmost label of the REGISTRABLE DOMAIN (NOT the leftmost label of the full hostname). Strip subdomain prefixes. Examples:
  finance.contoso.com   → registrable = contoso.com    → app: "contoso"
  sso.fabrikam.com       → registrable = contoso.com    → app: "contoso"
  admin.contoso.azurewebsites.net  → registrable = contoso.com    → app: "contoso"   (NOT "contoso")
  api.app.fabrikam.azurewebsites.net → registrable = contoso.com → app: "contoso" (NOT "contoso")
DEDUPLICATE the app-name list — if 17 hostnames map to "contoso", the unique list has 1 entry "contoso", not 17. You will run STEP 3 PASS B once per UNIQUE app name.

============================================================
STEP 2 — Application identity
============================================================
For EACH hostname from step 1, call all three:
  search_recon({"source":"crtsh","target":"<hostname>"})
  search_recon({"source":"whatweb","target":"<hostname>"})
  search_findings({"source":"microburst","search":"<hostname>","limit":5000})
Bullet each (hostname → tenant_or_org). If unknown, "(no tenant found)".

============================================================
STEP 3 — Pivot to USERS associated with each app
============================================================
TWO passes. Run both — they catch different data.

PASS A — by tenant (only when STEP 2 found one). For each distinct tenant:
  search_identities({"provider":"microburst","search":"<tenant_or_domain>","limit":5000})
NOTE: if PASS A returns 0, that's expected — the identities table may not have MicroBurst data. PASS B is what actually finds users.

PASS B — by APP NAME (MANDATORY, run for EACH UNIQUE app name from step 1):
  search_findings({"source":"microburst","search":"<app_name>","limit":5000})
  ☆ source="microburst" is REQUIRED. Without it you get web vulns instead of users. ☆

PROCESS the search_findings result (each row has finding_type and data):
  - Skip rows where finding_type = 'azure_group' — those are groups, not users.
  - For rows where finding_type = 'azure_user': extract data.row.UserPrincipalName → user.
  - For rows where finding_type = 'azure_group_member': extract data.row.UserPrincipalName → user. Also note data.row.`Group Name` as context (e.g. "AAD-ServiceAccounts", "Domain Admins").
  - Deduplicate users by UserPrincipalName.

OUTPUT: bullet each unique UPN, grouped by app. Format:
  <UserPrincipalName>  (groups: <Group A>, <Group B>; via PASS B/app=<app>)
If 0 users across both passes for an app, write "STEP 3: 0 user accounts for app=<app_name>".

If search_findings returns rows where finding_type is NOT one of azure_user / azure_group_member / azure_group — IGNORE them. They are unrelated data sources (web findings, vulns, etc.) that happened to match the search string. The source="microburst" filter should already eliminate them, but stay strict.

============================================================
STEP 4 — FINAL TABLE
============================================================
Markdown table — one row per unique UserPrincipalName from step 3:

| UserPrincipalName | groups (sample, max 3) | suggested Azure app to spray (hostname — provider_evidence) |
| ----------------- | ---------------------- | --------------------------------------------------------- |

Match users to AWS apps by APP NAME. If a user surfaced via app="contoso", pair them with ALL *.contoso.com hostnames from step 1 (or pick the most relevant: sso.*, login.*, app.*, admin.* in that priority order).

Then ONE summary line:
  Total users: N. Distinct groups: G. Azure apps reachable: H (= count from step 1).

That is the end of your response. Do not add commentary, suggestions, or questions. Begin STEP 1 now.$$,
       ARRAY['engagement']::text[],
       ARRAY['cloud', 'azure', 'identity', 'microburst', 'pivot']::text[],
       ARRAY['get_assets','search_recon','search_findings','search_identities']::text[],
       'system'
WHERE NOT EXISTS (
    SELECT 1 FROM public.chat_presets
    WHERE engagement_id IS NULL AND title = 'Azure infra → MicroBurst user pivot'
);


-- Idempotent: pin the AWS pivot preset's allowed_tools allowlist. Re-runs
-- of ensure_all_tables.sql update existing rows whose allowed_tools is NULL
-- or differs, keeping schema-as-code authoritative.
UPDATE public.chat_presets
SET allowed_tools = ARRAY[
    'get_assets',
    'search_recon',
    'search_findings',
    'search_identities'
]::text[]
WHERE engagement_id IS NULL AND title = 'AWS infra → MicroBurst user pivot'
  AND allowed_tools IS DISTINCT FROM ARRAY[
    'get_assets',
    'search_recon',
    'search_findings',
    'search_identities'
]::text[];

-- ============================================================================
-- Backfill: assets.provider from existing recon_findings
-- ============================================================================
-- One-time tagging pass per provider. Idempotent — only writes when the tag
-- isn't already present. Re-running is safe (no-op when fully tagged).
-- Signals scanned: dnsx CNAMEs, tlsx certs, httpx tech, asnmap org, whatweb.

-- AWS
WITH evidence AS (
    SELECT rf.asset_id,
           array_agg(DISTINCT
             CASE
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%amazonaws%'    THEN 'cname:amazonaws'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%cloudfront%'   THEN 'cname:cloudfront'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%elasticbeanstalk%' THEN 'cname:elasticbeanstalk'
               WHEN rf.finding_type = 'tls_cert'  AND rf.data::text ILIKE '%amazonaws%'    THEN 'tls:amazonaws'
               WHEN rf.finding_type = 'web_service' AND (rf.data::text ILIKE '%CloudFront%' OR rf.data::text ILIKE '%AmazonS3%' OR rf.data::text ILIKE '%AWSALB%') THEN 'http:aws-header'
               WHEN rf.source = 'asnmap'           AND rf.data::text ~* '(AS16509|AS14618|AS39111|Amazon)' THEN 'asn:amazon'
             END
           ) FILTER (WHERE
               (rf.finding_type = 'dns_cname' AND (rf.data::text ILIKE '%amazonaws%' OR rf.data::text ILIKE '%cloudfront%' OR rf.data::text ILIKE '%elasticbeanstalk%'))
            OR (rf.finding_type = 'tls_cert'  AND rf.data::text ILIKE '%amazonaws%')
            OR (rf.finding_type = 'web_service' AND (rf.data::text ILIKE '%CloudFront%' OR rf.data::text ILIKE '%AmazonS3%' OR rf.data::text ILIKE '%AWSALB%'))
            OR (rf.source = 'asnmap'           AND rf.data::text ~* '(AS16509|AS14618|AS39111|Amazon)')
           ) AS reasons
    FROM public.recon_findings rf
    WHERE rf.asset_id IS NOT NULL
    GROUP BY rf.asset_id
)
UPDATE public.assets a
SET provider = array_append(a.provider, 'aws'),
    provider_evidence = jsonb_set(a.provider_evidence, '{aws}', to_jsonb(e.reasons), true)
FROM evidence e
WHERE a.id = e.asset_id
  AND e.reasons IS NOT NULL
  AND array_length(e.reasons, 1) > 0
  AND NOT ('aws' = ANY(a.provider));

-- Azure
WITH evidence AS (
    SELECT rf.asset_id,
           array_agg(DISTINCT
             CASE
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%azurewebsites%'      THEN 'cname:azurewebsites'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%cloudapp.net%'       THEN 'cname:cloudapp'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%trafficmanager%'    THEN 'cname:trafficmanager'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%core.windows.net%'  THEN 'cname:azure-storage'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%onmicrosoft.com%'   THEN 'cname:onmicrosoft'
               WHEN rf.finding_type = 'tls_cert'  AND rf.data::text ILIKE '%microsoft%'         THEN 'tls:microsoft'
             END
           ) FILTER (WHERE
               (rf.finding_type = 'dns_cname' AND (
                   rf.data::text ILIKE '%azurewebsites%'
                OR rf.data::text ILIKE '%cloudapp.net%'
                OR rf.data::text ILIKE '%trafficmanager%'
                OR rf.data::text ILIKE '%core.windows.net%'
                OR rf.data::text ILIKE '%onmicrosoft.com%'))
            OR (rf.finding_type = 'tls_cert' AND rf.data::text ILIKE '%microsoft%')
           ) AS reasons
    FROM public.recon_findings rf
    WHERE rf.asset_id IS NOT NULL
    GROUP BY rf.asset_id
)
UPDATE public.assets a
SET provider = array_append(a.provider, 'azure'),
    provider_evidence = jsonb_set(a.provider_evidence, '{azure}', to_jsonb(e.reasons), true)
FROM evidence e
WHERE a.id = e.asset_id
  AND e.reasons IS NOT NULL
  AND array_length(e.reasons, 1) > 0
  AND NOT ('azure' = ANY(a.provider));

-- Cloudflare
WITH evidence AS (
    SELECT rf.asset_id,
           array_agg(DISTINCT
             CASE
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%cloudflare%'         THEN 'cname:cloudflare'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%cdnjs%'              THEN 'cname:cdnjs'
               WHEN rf.finding_type = 'dns_cname' AND rf.data::text ILIKE '%cloudflareaccess%'   THEN 'cname:cloudflareaccess'
               WHEN rf.finding_type = 'web_service' AND rf.data::text ILIKE '%cloudflare%'       THEN 'http:cloudflare'
               WHEN rf.source = 'asnmap'           AND rf.data::text ~* '(AS13335|Cloudflare)'   THEN 'asn:cloudflare'
             END
           ) FILTER (WHERE
               (rf.finding_type = 'dns_cname' AND (
                   rf.data::text ILIKE '%cloudflare%'
                OR rf.data::text ILIKE '%cdnjs%'
                OR rf.data::text ILIKE '%cloudflareaccess%'))
            OR (rf.finding_type = 'web_service' AND rf.data::text ILIKE '%cloudflare%')
            OR (rf.source = 'asnmap'           AND rf.data::text ~* '(AS13335|Cloudflare)')
           ) AS reasons
    FROM public.recon_findings rf
    WHERE rf.asset_id IS NOT NULL
    GROUP BY rf.asset_id
)
UPDATE public.assets a
SET provider = array_append(a.provider, 'cloudflare'),
    provider_evidence = jsonb_set(a.provider_evidence, '{cloudflare}', to_jsonb(e.reasons), true)
FROM evidence e
WHERE a.id = e.asset_id
  AND e.reasons IS NOT NULL
  AND array_length(e.reasons, 1) > 0
  AND NOT ('cloudflare' = ANY(a.provider));

-- ============================================================================
-- TIER 23: Background Installation Tasks
-- ============================================================================
-- Tracks software installation and WireGuard setup tasks that run independently
-- of HTTP requests, allowing users to close the GUI without stopping installations.
CREATE TABLE IF NOT EXISTS public.installation_tasks (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id           uuid REFERENCES public.remote_nodes(id) ON DELETE CASCADE,
    task_type         text NOT NULL, -- 'software' or 'wireguard'
    status            text NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'completed', 'failed'
    tools             text[] DEFAULT '{}'::text[], -- for software installations
    progress_log      jsonb NOT NULL DEFAULT '[]'::jsonb, -- array of progress events
    error_message     text,
    started_at        timestamptz,
    completed_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_installation_tasks_node     ON public.installation_tasks(node_id);
CREATE INDEX IF NOT EXISTS idx_installation_tasks_status   ON public.installation_tasks(status);
CREATE INDEX IF NOT EXISTS idx_installation_tasks_type     ON public.installation_tasks(task_type);
CREATE INDEX IF NOT EXISTS idx_installation_tasks_created  ON public.installation_tasks(created_at DESC);

-- ============================================================================
-- Summary
-- ============================================================================
SELECT 'ensure_all_tables.sql complete — schema is ready' as status;
SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;
