-- add_remote_nodes.sql
-- Tables for distributed scanning via Sliver C2 and Chisel tunnels
-- Safe to run multiple times (uses IF NOT EXISTS)

\connect scans

-- ===============================
-- remote_nodes: tracks connected remote scan nodes
-- ===============================
CREATE TABLE IF NOT EXISTS public.remote_nodes (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text NOT NULL,
    node_type         text NOT NULL CHECK (node_type IN ('sliver', 'chisel')),
    status            text NOT NULL DEFAULT 'offline'
                      CHECK (status IN ('online', 'offline', 'degraded', 'provisioning')),
    os                text,                   -- windows, linux, darwin
    hostname          text,
    internal_ip       inet,
    external_ip       inet,
    network_segment   text,                   -- e.g. "192.168.50.0/24 (Corp LAN)"
    proxy_port        integer CHECK (proxy_port IS NULL OR proxy_port BETWEEN 1 AND 65535),
    proxy_type        text DEFAULT 'socks5' CHECK (proxy_type IN ('socks5', 'socks4', 'http')),
    sliver_session_id text,                   -- Sliver session UUID (NULL for chisel nodes)
    chisel_client_id  text,                   -- Chisel fingerprint (NULL for sliver nodes)
    capabilities      jsonb DEFAULT '[]'::jsonb,  -- e.g. ["ad_attacks","port_scan","web_scan"]
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
CREATE UNIQUE INDEX IF NOT EXISTS ux_remote_nodes_ssh_host ON public.remote_nodes(hostname) WHERE node_type = 'ssh';
CREATE INDEX IF NOT EXISTS idx_remote_nodes_last_seen ON public.remote_nodes(last_seen DESC);

-- ===============================
-- node_scan_jobs: scans dispatched through remote nodes
-- ===============================
CREATE TABLE IF NOT EXISTS public.node_scan_jobs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         uuid NOT NULL REFERENCES public.remote_nodes(id) ON DELETE CASCADE,
    scan_type       text NOT NULL,            -- nmap, nuclei, web, etc.
    job_id          text,                     -- job_id from the scanner service
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    targets         jsonb DEFAULT '[]'::jsonb,
    parameters      jsonb DEFAULT '{}'::jsonb,
    result_summary  jsonb,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    completed_at    timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_node_scan_jobs_node_id ON public.node_scan_jobs(node_id);
CREATE INDEX IF NOT EXISTS idx_node_scan_jobs_status ON public.node_scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_node_scan_jobs_created_at ON public.node_scan_jobs(created_at DESC);

-- ===============================
-- ad_attack_results: Active Directory attack results via Sliver
-- ===============================
CREATE TABLE IF NOT EXISTS public.ad_attack_results (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         uuid NOT NULL REFERENCES public.remote_nodes(id) ON DELETE CASCADE,
    attack_type     text NOT NULL,            -- bloodhound, kerberoast, asreproast, dcsync, seatbelt, pth, enum_domain
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    target_domain   text,
    tool            text,                     -- Rubeus.exe, SharpHound.exe, Mimikatz, etc.
    command_used    text,
    output          text,
    parsed_results  jsonb DEFAULT '{}'::jsonb,
    findings_count  integer DEFAULT 0,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ad_attack_results_node_id ON public.ad_attack_results(node_id);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_attack_type ON public.ad_attack_results(attack_type);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_status ON public.ad_attack_results(status);
CREATE INDEX IF NOT EXISTS idx_ad_attack_results_created_at ON public.ad_attack_results(created_at DESC);

-- ===============================
-- node_ip_history: tracks every IP assignment/release per node
-- ===============================
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

-- ===============================
-- Triggers for updated_at
-- ===============================
DO $$
BEGIN
  IF to_regclass('public.remote_nodes') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_remote_nodes_updated_at ON public.remote_nodes;
    CREATE TRIGGER trg_remote_nodes_updated_at
      BEFORE UPDATE ON public.remote_nodes
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF to_regclass('public.node_scan_jobs') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_node_scan_jobs_updated_at ON public.node_scan_jobs;
    CREATE TRIGGER trg_node_scan_jobs_updated_at
      BEFORE UPDATE ON public.node_scan_jobs
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

DO $$
BEGIN
  IF to_regclass('public.ad_attack_results') IS NOT NULL THEN
    DROP TRIGGER IF EXISTS trg_ad_attack_results_updated_at ON public.ad_attack_results;
    CREATE TRIGGER trg_ad_attack_results_updated_at
      BEFORE UPDATE ON public.ad_attack_results
      FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
  END IF;
END$$;

-- ===============================
-- Permissions
-- ===============================
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app;

SELECT 'Remote nodes tables created!' as status;
