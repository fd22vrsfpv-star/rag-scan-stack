-- add_missing_tables.sql
-- Migration to add missing tables to scans database
-- Run this after setup_alldb.sql if tables are missing

\connect scans

-- ===============================
-- web_findings table (CRITICAL - used by web_scanner.py)
-- ===============================
CREATE TABLE IF NOT EXISTS public.web_findings (
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
    cwe          text[],  -- Common Weakness Enumeration IDs
    refs         jsonb DEFAULT '{}'::jsonb,  -- External references/links (renamed from 'references' - reserved keyword)
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_web_findings_asset_id ON public.web_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_web_findings_url ON public.web_findings(url);
CREATE INDEX IF NOT EXISTS idx_web_findings_source ON public.web_findings(source);
CREATE INDEX IF NOT EXISTS idx_web_findings_severity ON public.web_findings(severity);
CREATE INDEX IF NOT EXISTS idx_web_findings_created_at ON public.web_findings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_web_findings_url_hash ON public.web_findings(md5(url));  -- For deduplication

-- ===============================
-- vulns table (CRITICAL - used by api.py /vulns endpoint)
-- ===============================
CREATE TABLE IF NOT EXISTS public.vulns (
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

CREATE INDEX IF NOT EXISTS idx_vulns_asset_id ON public.vulns(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulns_port_id ON public.vulns(port_id);
CREATE INDEX IF NOT EXISTS idx_vulns_script ON public.vulns(script);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON public.vulns(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cve_gin ON public.vulns USING GIN (cve);
CREATE INDEX IF NOT EXISTS idx_vulns_created_at ON public.vulns(created_at DESC);

-- ===============================
-- scan_recommendations table (used by scan_recommender.py)
-- ===============================
CREATE TABLE IF NOT EXISTS public.scan_recommendations (
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

-- Create a generated fingerprint column for deduplication
ALTER TABLE public.scan_recommendations
    ADD COLUMN IF NOT EXISTS fingerprint text
    GENERATED ALWAYS AS (
        md5(COALESCE(ip::text, '') || '|' ||
            COALESCE(service, '') || '|' ||
            COALESCE(scanner, '') || '|' ||
            COALESCE(action, '') || '|' ||
            COALESCE(script, '') || '|' ||
            COALESCE(template, ''))
    ) STORED;

CREATE UNIQUE INDEX IF NOT EXISTS ux_scan_recommendations_fingerprint
    ON public.scan_recommendations(fingerprint);

CREATE INDEX IF NOT EXISTS idx_scan_recommendations_asset_id ON public.scan_recommendations(asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_ip ON public.scan_recommendations(ip);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_scanner ON public.scan_recommendations(scanner);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_status ON public.scan_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_priority ON public.scan_recommendations(priority DESC);
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_created_at ON public.scan_recommendations(created_at DESC);

-- ===============================
-- playwright_scans table (for Phase 2)
-- ===============================
CREATE TABLE IF NOT EXISTS public.playwright_scans (
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

CREATE INDEX IF NOT EXISTS idx_playwright_scans_asset_id ON public.playwright_scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_url ON public.playwright_scans(url);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_status ON public.playwright_scans(status);
CREATE INDEX IF NOT EXISTS idx_playwright_scans_created_at ON public.playwright_scans(created_at DESC);

-- ===============================
-- playwright_findings table (for Phase 2)
-- ===============================
CREATE TABLE IF NOT EXISTS public.playwright_findings (
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

CREATE INDEX IF NOT EXISTS idx_playwright_findings_scan_id ON public.playwright_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_asset_id ON public.playwright_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_url ON public.playwright_findings(url);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_type ON public.playwright_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_severity ON public.playwright_findings(severity);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_cwe_gin ON public.playwright_findings USING GIN (cwe);
CREATE INDEX IF NOT EXISTS idx_playwright_findings_created_at ON public.playwright_findings(created_at DESC);

-- ===============================
-- playwright_screenshots table (for Phase 2)
-- ===============================
CREATE TABLE IF NOT EXISTS public.playwright_screenshots (
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

CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_scan_id ON public.playwright_screenshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_url ON public.playwright_screenshots(url);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_hash ON public.playwright_screenshots(image_hash);
CREATE INDEX IF NOT EXISTS idx_playwright_screenshots_created_at ON public.playwright_screenshots(created_at DESC);

-- ===============================
-- dom_analysis table (for Phase 2 - client-side security analysis)
-- ===============================
CREATE TABLE IF NOT EXISTS public.dom_analysis (
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

CREATE INDEX IF NOT EXISTS idx_dom_analysis_scan_id ON public.dom_analysis(scan_id);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_asset_id ON public.dom_analysis(asset_id);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_url ON public.dom_analysis(url);
CREATE INDEX IF NOT EXISTS idx_dom_analysis_created_at ON public.dom_analysis(created_at DESC);

-- ===============================
-- zap_sessions table (to link ZAP scans with other scans)
-- ===============================
CREATE TABLE IF NOT EXISTS public.zap_sessions (
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

CREATE INDEX IF NOT EXISTS idx_zap_sessions_playwright_scan_id ON public.zap_sessions(playwright_scan_id);
CREATE INDEX IF NOT EXISTS idx_zap_sessions_created_at ON public.zap_sessions(created_at DESC);

-- ===============================
-- kb_service_overrides table (Knowledge Base user edits overlay)
-- ===============================
CREATE TABLE IF NOT EXISTS public.kb_service_overrides (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name text NOT NULL UNIQUE,
    data         jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kb_service_overrides_name ON public.kb_service_overrides(service_name);

-- ===============================
-- Triggers for updated_at columns
-- ===============================

-- web_findings trigger
DROP TRIGGER IF EXISTS trg_web_findings_updated_at ON public.web_findings;
CREATE TRIGGER trg_web_findings_updated_at
    BEFORE UPDATE ON public.web_findings
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- vulns trigger
DROP TRIGGER IF EXISTS trg_vulns_updated_at ON public.vulns;
CREATE TRIGGER trg_vulns_updated_at
    BEFORE UPDATE ON public.vulns
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- scan_recommendations trigger
DROP TRIGGER IF EXISTS trg_scan_recommendations_updated_at ON public.scan_recommendations;
CREATE TRIGGER trg_scan_recommendations_updated_at
    BEFORE UPDATE ON public.scan_recommendations
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- playwright_scans trigger
DROP TRIGGER IF EXISTS trg_playwright_scans_updated_at ON public.playwright_scans;
CREATE TRIGGER trg_playwright_scans_updated_at
    BEFORE UPDATE ON public.playwright_scans
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- playwright_findings trigger
DROP TRIGGER IF EXISTS trg_playwright_findings_updated_at ON public.playwright_findings;
CREATE TRIGGER trg_playwright_findings_updated_at
    BEFORE UPDATE ON public.playwright_findings
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- zap_sessions trigger
DROP TRIGGER IF EXISTS trg_zap_sessions_updated_at ON public.zap_sessions;
CREATE TRIGGER trg_zap_sessions_updated_at
    BEFORE UPDATE ON public.zap_sessions
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- kb_service_overrides trigger
DROP TRIGGER IF EXISTS trg_kb_service_overrides_updated_at ON public.kb_service_overrides;
CREATE TRIGGER trg_kb_service_overrides_updated_at
    BEFORE UPDATE ON public.kb_service_overrides
    FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- ===============================
-- Grant permissions
-- ===============================
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scans;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scans;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO scans;

-- Also grant to app user if different from scans
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app') THEN
        GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app;
        GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app;
    END IF;
END$$;

-- ===============================
-- Helpful views
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
-- Verification queries
-- ===============================

-- Uncomment to verify tables were created:
-- SELECT table_name FROM information_schema.tables
-- WHERE table_schema = 'public'
-- AND table_name IN ('web_findings', 'vulns', 'scan_recommendations',
--                    'playwright_scans', 'playwright_findings',
--                    'playwright_screenshots', 'dom_analysis', 'zap_sessions')
-- ORDER BY table_name;
