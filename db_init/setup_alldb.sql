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

-- ── Normalize asset identity so port data is not duplicated per IP ──
--
-- ix_assets_ip_hostname is UNIQUE(ip, COALESCE(hostname,'')) on purpose, so one
-- IP may legitimately hold several asset rows (virtual hosts). But a hostname
-- that is merely the IP string is not a vhost — it is "hostname unknown"
-- written the wrong way, and it counts as a DIFFERENT row from hostname=NULL.
-- Ports hang off asset_id, so each such row carried its own copy of that host's
-- ports: this deployment had 99 port rows for 59 real (ip, proto, port) tuples.
--
-- Root cause was playwright_scanner calling
-- get_or_create_asset(netloc, hostname=netloc). Fixed there and in both asset
-- helpers, with CHECK assets_hostname_not_ip as the schema-level backstop.
--
-- Runs as ONE transaction so a partial remap can never be left behind, and the
-- scratch tables use ON COMMIT DROP so the block is re-runnable in a session.
-- Idempotent: a no-op once normalized.
BEGIN;

-- 1. hostname == the IP means "hostname unknown". Normalize to NULL where that
--    does not collide with an existing NULL-hostname row for the same IP
--    (step 5 merges those).
UPDATE assets a
   SET hostname = NULL
 WHERE a.hostname = host(a.ip)
   AND NOT EXISTS (SELECT 1 FROM assets b
                    WHERE b.ip = a.ip AND b.hostname IS NULL AND b.id <> a.id);

-- 2. One canonical asset per IP owns that IP's network-level data. Ports are a
--    property of the host, not of a virtual host. Preference: the NULL-hostname
--    (IP-level) row, then oldest, id as a strict final tiebreaker.
CREATE TEMP TABLE canonical_asset ON COMMIT DROP AS
SELECT DISTINCT ON (ip) ip, id AS keep_id
  FROM assets ORDER BY ip, (hostname IS NULL) DESC, first_seen NULLS LAST, id;

CREATE TEMP TABLE asset_remap ON COMMIT DROP AS
SELECT a.id AS from_id, c.keep_id AS to_id
  FROM assets a JOIN canonical_asset c ON c.ip = a.ip
 WHERE a.id <> c.keep_id;

-- 3. Resolve each port to its DESTINATION asset first, then pick one winner per
--    (destination, proto, port). Deduping only against rows already at the
--    target is not enough: several source assets can remap to the same
--    canonical, and their port sets then collide with each other rather than
--    with the target. That is exactly how the first draft of this migration
--    failed, on ux_ports_asset_proto_port_scans.
CREATE TEMP TABLE port_target ON COMMIT DROP AS
SELECT p.id, COALESCE(r.to_id, p.asset_id) AS target_asset, p.proto, p.port
  FROM ports p LEFT JOIN asset_remap r ON r.from_id = p.asset_id;

CREATE TEMP TABLE port_keep ON COMMIT DROP AS
SELECT DISTINCT ON (t.target_asset, t.proto, t.port) t.id
  FROM port_target t JOIN ports p ON p.id = t.id
 ORDER BY t.target_asset, t.proto, t.port, p.last_seen DESC NULLS LAST, p.id;

-- Fold the losers' detail into the winner, so a merge never loses a banner or
-- version that only the duplicate row happened to carry.
UPDATE ports w
   SET first_seen = LEAST(w.first_seen, agg.min_first),
       last_seen  = GREATEST(w.last_seen, agg.max_last),
       service    = COALESCE(w.service, agg.service),
       product    = COALESCE(w.product, agg.product),
       version    = COALESCE(w.version, agg.version),
       banner     = COALESCE(w.banner,  agg.banner),
       is_open    = w.is_open OR agg.any_open
  FROM (SELECT k.id AS win_id,
               MIN(p.first_seen) AS min_first, MAX(p.last_seen) AS max_last,
               MIN(p.service) AS service, MIN(p.product) AS product,
               MIN(p.version) AS version, MIN(p.banner) AS banner,
               bool_or(COALESCE(p.is_open, false)) AS any_open
          FROM port_keep k
          JOIN port_target t  ON t.id = k.id
          JOIN port_target t2 ON t2.target_asset = t.target_asset
                             AND t2.proto = t.proto AND t2.port = t.port
          JOIN ports p ON p.id = t2.id
         GROUP BY k.id) agg
 WHERE w.id = agg.win_id;

DELETE FROM ports WHERE id IN (
    SELECT id FROM port_target EXCEPT SELECT id FROM port_keep);

UPDATE ports p SET asset_id = r.to_id
  FROM asset_remap r WHERE p.asset_id = r.from_id;

-- 4. port_observation is an append-only observation log with no uniqueness on
--    (asset_id, proto, port) — many rows per port is the point. Repoint only.
UPDATE port_observation o SET asset_id = r.to_id
  FROM asset_remap r WHERE o.asset_id = r.from_id;

-- 5. A "hostname = the IP" row is the same host as its NULL-hostname sibling.
--    Repoint its remaining children and drop it. `ports` is the ONLY child with
--    a unique index on asset_id and is already handled above, so the rest
--    cannot collide. scan_recommendations.fingerprint is generated from
--    ip/service/scanner/action/script/template — not asset_id — so repointing
--    does not change it.
CREATE TEMP TABLE phantom_remap ON COMMIT DROP AS
SELECT a.id AS from_id, b.id AS to_id
  FROM assets a
  JOIN assets b ON b.ip = a.ip AND b.hostname IS NULL AND b.id <> a.id
 WHERE a.hostname = host(a.ip);

UPDATE web_findings         t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE vulns                t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE playwright_scans     t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE playwright_findings  t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE dom_analysis         t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE content_extractions  t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE discovered_params    t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE credential_findings  t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE recon_findings       t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE scan_recommendations t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE scan_targets         t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE findings             t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE attack_vectors       t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE attack_path_edges    t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE port_observation     t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;
UPDATE ports                t SET asset_id = p.to_id FROM phantom_remap p WHERE t.asset_id = p.from_id;

UPDATE assets k
   SET first_seen = LEAST(k.first_seen, a.first_seen),
       last_seen  = GREATEST(k.last_seen, a.last_seen),
       os         = COALESCE(k.os, a.os)
  FROM phantom_remap p JOIN assets a ON a.id = p.from_id
 WHERE k.id = p.to_id;

DELETE FROM assets WHERE id IN (SELECT from_id FROM phantom_remap);

-- 5b. One address, two asset rows — the SAME machine recorded twice.
--
-- Step 5 above only merges the "hostname = the IP" phantom. It deliberately
-- leaves a genuinely-named row alone, to protect virtual hosts. But a row with
-- NO hostname is not a virtual host: it is the same machine before its name was
-- known. ix_assets_ip_hostname is UNIQUE(ip, COALESCE(hostname,'')), so
-- (192.168.1.150, '') and (192.168.1.150, 'metasploitable') are two legal rows,
-- and this deployment had exactly that:
--
--     nameless row     57 ports,  6 vulns,   1 web,   0 creds,  39 recon
--     'metasploitable'  0 ports,  2 vulns, 758 web,   7 creds, 110 recon
--
-- Step 2 puts ports on the NULL-hostname row by preference, so the host's ports
-- lived on one row and its findings on the other. Anything joining ports to
-- findings through asset_id returned nothing, and credential_findings.port_id
-- was NULL on every row because parse_brutus looks the port up under the
-- finding's own asset_id.
--
-- Merging is only safe when at most ONE distinct hostname is involved. Two
-- different names on one address IS a multi-name host, where picking a survivor
-- would be arbitrary — those are reported and left alone.
--
-- The child tables come from the CATALOG, not from the foreign-key list:
-- pending_exploits.asset_id has no FK, so an FK-driven merge would silently
-- orphan it, and step 5's hand-written list of 16 tables omits it for that
-- reason. Anything that grows an asset_id later is covered without edits here.
CREATE OR REPLACE FUNCTION public.merge_duplicate_assets()
RETURNS TABLE(address inet, winner uuid, losers integer, rows_repointed bigint)
LANGUAGE plpgsql AS $MDA$
DECLARE
    child_tables text[];
    grp          record;
    cand         record;
    tbl          text;
    n            bigint;
    kids         bigint;
    best_kids    bigint;
    win          uuid;
    losers_arr   uuid[];
    moved        bigint;
    rid          uuid;
    agg          record;
BEGIN
    SELECT array_agg(c.table_name::text ORDER BY c.table_name) INTO child_tables
      FROM information_schema.columns c
      JOIN information_schema.tables t
        ON t.table_schema = c.table_schema AND t.table_name = c.table_name
     WHERE c.table_schema = 'public'
       AND c.column_name = 'asset_id'
       AND t.table_type = 'BASE TABLE';

    FOR grp IN
        SELECT a.ip
          FROM public.assets a
         GROUP BY a.ip
        HAVING count(*) > 1
           -- count(DISTINCT ...) ignores NULLs, so (NULL, 'name') counts as one
           -- name and merges; ('a', 'b') counts as two and does not.
           AND count(DISTINCT NULLIF(btrim(a.hostname), '')) <= 1
         ORDER BY a.ip
    LOOP
        -- Survivor: the row carrying the most dependent rows, so the merge moves
        -- as little as possible. The ORDER BY makes ties deterministic and
        -- prefers keeping the NAMED row, which holds strictly more information.
        best_kids := -1;
        win       := NULL;
        FOR cand IN
            SELECT id FROM public.assets
             WHERE ip = grp.ip
             ORDER BY (NULLIF(btrim(hostname), '') IS NOT NULL) DESC,
                      first_seen NULLS LAST, id
        LOOP
            kids := 0;
            FOREACH tbl IN ARRAY child_tables LOOP
                EXECUTE format('SELECT count(*) FROM public.%I WHERE asset_id = $1', tbl)
                   INTO n USING cand.id;
                kids := kids + n;
            END LOOP;
            IF kids > best_kids THEN
                best_kids := kids;
                win       := cand.id;
            END IF;
        END LOOP;

        SELECT array_agg(id) INTO losers_arr
          FROM public.assets WHERE ip = grp.ip AND id <> win;
        IF losers_arr IS NULL THEN
            CONTINUE;
        END IF;

        moved := 0;
        FOREACH tbl IN ARRAY child_tables LOOP
            BEGIN
                EXECUTE format(
                    'UPDATE public.%I SET asset_id = $1 WHERE asset_id = ANY($2)', tbl)
                  USING win, losers_arr;
                GET DIAGNOSTICS n = ROW_COUNT;
                moved := moved + n;
            EXCEPTION WHEN unique_violation THEN
                -- Today only ports has a unique index naming asset_id, but do not
                -- depend on that staying true. Move what can move; a child that
                -- already exists on the survivor is the same fact twice, so the
                -- loser's copy goes rather than blocking the whole merge.
                FOR rid IN EXECUTE format(
                        'SELECT id FROM public.%I WHERE asset_id = ANY($1)', tbl)
                        USING losers_arr
                LOOP
                    BEGIN
                        EXECUTE format(
                            'UPDATE public.%I SET asset_id = $1 WHERE id = $2', tbl)
                          USING win, rid;
                        moved := moved + 1;
                    EXCEPTION WHEN unique_violation THEN
                        EXECUTE format('DELETE FROM public.%I WHERE id = $1', tbl)
                          USING rid;
                    END;
                END LOOP;
            END;
        END LOOP;

        -- Read the losers' attributes BEFORE deleting them, then apply them AFTER.
        --
        -- The order is load-bearing. When the nameless row is the one carrying
        -- the children it wins, and giving it the loser's hostname while that
        -- loser still exists violates ix_assets_ip_hostname:
        --     duplicate key value ... (198.51.100.11, merge-probe.test)
        -- The live split happened to have the NAMED row winning, so its hostname
        -- never changed and this never fired there — a synthetic case found it.
        SELECT min(NULLIF(btrim(a.hostname), ''))       AS hostname,
               min(a.os)                                AS os,
               min(a.env)                               AS env,
               min(a.content_hash)                      AS content_hash,
               min(a.engagement_id::text)::uuid         AS engagement_id,
               array_agg(DISTINCT t)  FILTER (WHERE t  IS NOT NULL) AS tags,
               array_agg(DISTINCT pr) FILTER (WHERE pr IS NOT NULL) AS provider,
               min(a.provider_evidence::text)::jsonb    AS provider_evidence,
               min(a.first_seen)                        AS first_seen,
               max(a.last_seen)                         AS last_seen
          INTO agg
          FROM public.assets a
          LEFT JOIN LATERAL unnest(COALESCE(a.tags, '{}'::text[]))     t  ON true
          LEFT JOIN LATERAL unnest(COALESCE(a.provider, '{}'::text[])) pr ON true
         WHERE a.id = ANY(losers_arr);

        DELETE FROM public.assets WHERE id = ANY(losers_arr);

        -- A merge must never drop the one attribute a duplicate row happened to
        -- be the only carrier of — the hostname above all, which is the whole
        -- reason the second row existed.
        UPDATE public.assets w
           SET hostname          = COALESCE(NULLIF(btrim(w.hostname), ''), agg.hostname),
               os                = COALESCE(w.os, agg.os),
               env               = COALESCE(w.env, agg.env),
               content_hash      = COALESCE(w.content_hash, agg.content_hash),
               engagement_id     = COALESCE(w.engagement_id, agg.engagement_id),
               tags              = (SELECT array_agg(DISTINCT x) FROM unnest(
                                       COALESCE(w.tags, '{}'::text[])
                                    || COALESCE(agg.tags, '{}'::text[])) x),
               provider          = (SELECT array_agg(DISTINCT x) FROM unnest(
                                       COALESCE(w.provider, '{}'::text[])
                                    || COALESCE(agg.provider, '{}'::text[])) x),
               -- winner's keys win on conflict
               provider_evidence = COALESCE(agg.provider_evidence, '{}'::jsonb)
                                || COALESCE(w.provider_evidence, '{}'::jsonb),
               first_seen        = LEAST(w.first_seen, agg.first_seen),
               last_seen         = GREATEST(w.last_seen, agg.last_seen),
               modified_at       = now()
         WHERE w.id = win;

        address        := grp.ip;
        winner         := win;
        losers         := array_length(losers_arr, 1);
        rows_repointed := moved;
        RETURN NEXT;
    END LOOP;

    -- Report rather than silently skip. An address holding two DIFFERENT
    -- hostnames is a real multi-name host, and an operator should know it is
    -- being left alone instead of wondering why the count never drops.
    FOR grp IN
        SELECT a.ip, count(*) AS n
          FROM public.assets a
         GROUP BY a.ip
        HAVING count(*) > 1
           AND count(DISTINCT NULLIF(btrim(a.hostname), '')) > 1
    LOOP
        RAISE NOTICE 'assets: % has % rows with different hostnames (virtual hosts) - left unmerged', grp.ip, grp.n;
    END LOOP;
END $MDA$;

DO $RUNMDA$
DECLARE r record; BEGIN
    FOR r IN SELECT * FROM public.merge_duplicate_assets() LOOP
        RAISE NOTICE 'assets: merged % duplicate row(s) for % into %, repointed % child row(s)',
                     r.losers, r.address, r.winner, r.rows_repointed;
    END LOOP;
END $RUNMDA$;


-- 5c. Backfill credential_findings.port_id, which was NULL on every row.
--
-- parse_brutus resolves the port with
--     SELECT id FROM ports WHERE asset_id = <finding's asset> AND port = <port>
-- and the finding attached to the nameless asset row that had no ports, so the
-- lookup found nothing and the column stayed empty. 5b puts the ports and the
-- credentials on the same asset, which makes the lookup work — but only for rows
-- ingested from here on. This fills in the ones already stored.
--
-- Matched on (asset, port) only: ports.proto is the TRANSPORT ('tcp'), while
-- credential_findings.protocol is the SERVICE ('ftp', 'telnet'), so they are not
-- comparable. tcp is preferred because credential testing is TCP.
UPDATE public.credential_findings cf
   SET port_id = p.id
  FROM public.ports p
 WHERE cf.port_id IS NULL
   AND p.asset_id = cf.asset_id
   AND p.port     = cf.port
   AND p.id = (SELECT p2.id FROM public.ports p2
                WHERE p2.asset_id = cf.asset_id AND p2.port = cf.port
                ORDER BY (p2.proto = 'tcp') DESC, p2.last_seen DESC NULLS LAST, p2.id
                LIMIT 1);

-- A scan refused by the scope gate is 'blocked', not 'failed'.
--
-- CLAUDE.md: "Blocked items MUST be labelled in the UI, not silently dropped."
-- Folding a refusal into 'failed' invites a retry of something that will never
-- be allowed to run. The CREATE TABLE above predates the gate, so the value is
-- added here for databases that already exist.
DO $PWB$ BEGIN
    ALTER TABLE public.playwright_scans
        DROP CONSTRAINT IF EXISTS playwright_scans_status_check;
    ALTER TABLE public.playwright_scans
        ADD CONSTRAINT playwright_scans_status_check
        CHECK (status IN ('queued','running','completed','failed','blocked'));
EXCEPTION WHEN undefined_table THEN NULL; END $PWB$;

-- 6. Prevent recurrence. NOT VALID so a pre-existing violation can never block
--    this migration; steps 1 and 5 have already cleared them.
DO $NORM$ BEGIN
    ALTER TABLE public.assets
      ADD CONSTRAINT assets_hostname_not_ip
      CHECK (hostname IS NULL OR hostname <> host(ip)) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL; END $NORM$;

COMMIT;

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
                   CHECK (status IN ('queued','running','completed','failed','blocked')),
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
      -- CAUTION: PLAINTEXT credential material, by operator decision. A
      -- recovered password is the primary artefact of a credential-testing
      -- phase and lateral movement needs the real secret. /export/data carries
      -- it (the `credentials` category is on by default and reads SELECT *),
      -- so an export file is as sensitive as this table. metadata.audit stays
      -- masked: it lists every password TRIED, most belonging to no account.
      secret_value  text,
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
                          CHECK (status IN ('active','completed','failed','stopped','stalled','awaiting_approval')),
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
  -- One row per (session, job). REQUIRED by the upsert in
  -- autogen_agents/scan_tools.py::persist_to_db — without it the
  -- ON CONFLICT (session_id, job_id) clause raises at runtime.
  --
  -- Created outside the table guard so existing installs pick it up too; the
  -- matching dedupe-then-create migration lives in ensure_all_tables.sql.
  CREATE UNIQUE INDEX IF NOT EXISTS uq_session_scan_metrics_session_job
      ON public.session_scan_metrics(session_id, job_id);
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

-- Finding deduplication (see ensure_all_tables.sql for the dedupe migration that
-- existing databases need first). CLAUDE.md requires fingerprint-based dedup and
-- first/last seen; etl/fingerprint.py computes the hashes and the parsers upsert
-- with ON CONFLICT (fingerprint), which REQUIRES these indexes to exist.
CREATE UNIQUE INDEX IF NOT EXISTS uq_web_findings_fingerprint
    ON public.web_findings(fingerprint);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vulns_fingerprint
    ON public.vulns(fingerprint);

-- One credential finding per account.
--
-- Total, not partial, and coalesced on auth_type. The previous version was
-- partial on `username IS NOT NULL`, which is dead — username is NOT NULL in
-- this schema. The real hole was auth_type: it IS nullable, and a NULL makes
-- rows non-equal for a unique index, so two rows with the same
-- (ip, port, username) and a NULL auth_type were both stored. Demonstrated:
-- two identical inserts with auth_type NULL both landed, while the same pair
-- with auth_type='password' was correctly rejected.
--
-- Required by the ON CONFLICT in etl/parse_brutus.py, which must repeat this
-- expression EXACTLY or Postgres raises "no unique or exclusion constraint
-- matching the ON CONFLICT specification" on every row.
CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_findings_identity
    ON public.credential_findings(ip, port, username, COALESCE(auth_type, ''));
-- ── credential_findings: fingerprint dedup, matching the other finding tables ──
--
-- This table deduped on an identity INDEX while vulns, web_findings and
-- recon_findings all dedupe on a fingerprint COLUMN plus a trigger. Two
-- mechanisms for one concept means every reader has to know which table works
-- which way, and only the fingerprint tables get a stable id for exports and
-- the delta view.
--
-- discovered_at / last_verified_at already serve first_seen / last_seen here,
-- so no new timestamp columns are needed — but nothing was bumping
-- last_verified_at except the ON CONFLICT in etl/parse_brutus.py. The trigger
-- now does it for every writer.
DO $$ BEGIN ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS fingerprint text; EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- Must match etl/fingerprint.py::credential_fingerprint EXACTLY, or a row
-- written by a Python-side writer and one written by a raw INSERT of the same
-- account would not recognise each other. tests/test_fingerprint.py pins both
-- to a shared case table and exercises this through the real trigger.
--
-- valid_cred and status are deliberately NOT hashed: a credential that stopped
-- working is the same account, and hashing the outcome would add a row every
-- time the result flipped.
CREATE OR REPLACE FUNCTION public.credential_findings_dedup() RETURNS trigger AS $fn$
DECLARE
    existing_id uuid;
BEGIN
    IF NEW.fingerprint IS NULL THEN
        NEW.fingerprint := md5('cred|' || coalesce(host(NEW.ip), '')
                               || '|' || CASE WHEN NEW.port IS NOT NULL AND NEW.port <> 0
                                              THEN NEW.port::text ELSE '0' END
                               || '|' || lower(btrim(coalesce(NEW.username, '')))
                               || '|' || lower(btrim(coalesce(NEW.auth_type, ''))));
    END IF;

    SELECT id INTO existing_id
      FROM public.credential_findings WHERE fingerprint = NEW.fingerprint;

    IF FOUND THEN
        -- Re-testing a known credential is a re-verification, not a new
        -- finding. This mirrors what the ON CONFLICT in etl/parse_brutus.py
        -- used to be solely responsible for, so every writer now gets it.
        UPDATE public.credential_findings
           SET last_verified_at = now(),
               valid_cred       = COALESCE(NEW.valid_cred, valid_cred),
               status           = COALESCE(NEW.status, status),
               secret_type      = COALESCE(NEW.secret_type, secret_type),
               banner           = COALESCE(NEW.banner, banner),
               metadata         = COALESCE(NEW.metadata, metadata),
               -- The recovered secret. A re-verification often DOES
               -- capture the password when the first observation did
               -- not, and without this the new value is discarded: this
               -- trigger RETURNs NULL on a duplicate, so the writer's own
               -- ON CONFLICT DO UPDATE never runs and there is no other
               -- path by which secret_value can reach an existing row.
               -- COALESCE, never assignment: a run that did not recover
               -- the password must not erase one already stored.
               secret_value     = COALESCE(NEW.secret_value, secret_value)
         WHERE id = existing_id;
        RETURN NULL;   -- skip the INSERT
    END IF;

    IF NEW.discovered_at IS NULL THEN NEW.discovered_at := now(); END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_credential_findings_dedup ON public.credential_findings;
CREATE TRIGGER trg_credential_findings_dedup
    BEFORE INSERT ON public.credential_findings
    FOR EACH ROW EXECUTE FUNCTION public.credential_findings_dedup();

-- Backfill existing rows through the same expression the trigger uses.
UPDATE public.credential_findings
   SET fingerprint = md5('cred|' || coalesce(host(ip), '')
                         || '|' || CASE WHEN port IS NOT NULL AND port <> 0
                                        THEN port::text ELSE '0' END
                         || '|' || lower(btrim(coalesce(username, '')))
                         || '|' || lower(btrim(coalesce(auth_type, ''))))
 WHERE fingerprint IS NULL;

-- Collapse any rows that the case-insensitive username or coalesced auth_type
-- now considers identical but the old index treated as distinct.
DELETE FROM public.credential_findings a
 USING public.credential_findings b
 WHERE a.fingerprint = b.fingerprint
   AND a.id <> b.id
   -- Prefer a confirmed-valid row, then the most recently seen; id makes the
   -- ordering strict and total so exactly one row per group survives.
   AND (coalesce(a.valid_cred, false),
        coalesce(a.last_verified_at, a.discovered_at, a.created_at), a.id)
       < (coalesce(b.valid_cred, false),
          coalesce(b.last_verified_at, b.discovered_at, b.created_at), b.id);

-- Only the unique index. vulns and web_findings each carry a redundant plain
-- idx_*_fingerprint alongside their uq_*_fingerprint, which buys nothing -- a
-- unique btree already serves equality lookups -- and costs write throughput on
-- the highest-volume tables in the schema. Not propagating that here.
CREATE UNIQUE INDEX IF NOT EXISTS uq_credential_findings_fingerprint
    ON public.credential_findings(fingerprint);
-- ── Virtual-host grouping: one problem, N affected vhosts ──────────────────
--
-- web_findings.fingerprint hashes the URL, which contains the hostname, so a
-- server-level problem on shared hosting stores one row per vhost. That is
-- correct for app-level findings and wrong for infrastructure ones.
--
-- The fix GROUPS rather than merges: every per-vhost row is kept, and a second
-- host-independent key marks them as facets of one underlying problem. Because
-- nothing is merged, the grouping key can be heuristic without risking data
-- loss — which is why no scope classifier is needed.
--
-- Must match etl/fingerprint.py::infrastructure_fingerprint EXACTLY.
DO $$ BEGIN ALTER TABLE public.web_findings ADD COLUMN IF NOT EXISTS infrastructure_fingerprint text; EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- ── web_findings: separate crawl INVENTORY from actual FINDINGS ────────────
--
-- 746 of 779 rows in this deployment are katana output: one row per discovered
-- URL, with no name and no issue_type. A crawled URL is not a finding, but they
-- were counted as one everywhere — the severity chart showed "recon: 782",
-- exports listed them, and the vhost rollup had almost nothing to group.
--
-- They are NOT junk, and must not be moved or deleted: /export/burp and
-- /export/har both read web_findings BY URL to build the Burp sitemap and the
-- HAR file, which is the tool's primary deliverable ("import into manual
-- tools"). The HAR query calls web_findings the "richest data for HAR".
--
-- So the fix is classification, not relocation. A generated column means no
-- writer has to be changed and the value cannot drift from the data it
-- describes.
--
-- Why not just filter severity='recon': whatweb and httpx use 'recon' for real,
-- NAMED findings. Severity conflates "informational finding" with "a URL we
-- merely saw". Absence of both name and issue_type is what actually
-- distinguishes them — and it is the same condition infrastructure_fingerprint
-- already uses to decide a row cannot be grouped, so the two stay consistent.
DO $$ BEGIN
    ALTER TABLE public.web_findings
      ADD COLUMN IF NOT EXISTS record_kind text
      GENERATED ALWAYS AS (
        CASE WHEN COALESCE(btrim(name), '') = ''
              AND COALESCE(btrim(issue_type), '') = ''
             THEN 'inventory' ELSE 'finding' END
      ) STORED;
EXCEPTION WHEN OTHERS THEN NULL; END $$;

-- Findings queries filter on this on every request, and inventory dominates the
-- table, so the index earns its keep.
CREATE INDEX IF NOT EXISTS idx_web_findings_record_kind
    ON public.web_findings(record_kind);

-- ── One numeric severity scale, in SQL ─────────────────────────────────────
--
-- Severity ordering was hand-written as a CASE expression in five places in
-- api.py alone, in three different conventions (ELSE 0, ELSE 4, ELSE 5, ELSE 7;
-- critical as 1 or as 5). Two of them also collapsed `low` and `info` together.
--
-- Higher = more severe, so `ORDER BY severity_rank(severity) DESC` reads the way
-- it sounds and an unknown value sorts LAST instead of first — which is the bug
-- the ascending copies had, since ELSE 7 put garbage above critical when someone
-- reversed the direction.
--
-- Must match etl/severity.py and the frontend's SEVERITY_RANK exactly;
-- tests/test_severity_scale.py pins all three to one case table.
--
-- IMMUTABLE so it can be used in an index and so the planner can fold it.
CREATE OR REPLACE FUNCTION public.severity_rank(sev text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT CASE lower(btrim(coalesce(sev, '')))
        WHEN 'critical' THEN 6
        WHEN 'high'     THEN 5
        WHEN 'medium'   THEN 4
        WHEN 'low'      THEN 3
        WHEN 'info'     THEN 2
        -- 'recon' is the pre-2026-08-22 name for 'info' and ranks identically,
        -- so rows written before that migration sort correctly rather than
        -- falling to unknown.
        WHEN 'recon'    THEN 2
        -- A failed scan is not a finding about the target; ranking it above
        -- informational output would push real results down.
        WHEN 'error'    THEN 1
        ELSE 0
    END
$$;

-- ── Collapse the 'recon' severity into 'info' ──────────────────────────────
--
-- The two were functionally identical. Measured before removing it:
--   * both mapped to SARIF level "note" — and 'recon' only by FALLTHROUGH,
--     since sev_map had no key for it
--   * both were ordinary severity chips in the UI, both included in reports
--   * no export, filter or report treated them differently
--   * the only difference was sort rank (info 5, recon 6)
-- A consumer had already given up on the distinction:
-- burp-extension/RagScanBridge.py buckets {"info","recon","informational",""}
-- as one thing.
--
-- attack_vectors is included because its severity is COPIED from the source
-- finding (app/rag-api/attack_vectors.py) — the same notion propagated, not a
-- different scale. 1495 of its rows carried 'recon' purely because the findings
-- they derive from did.
--
-- Idempotent: a second run matches nothing.
UPDATE public.web_findings   SET severity = 'info' WHERE severity = 'recon';
UPDATE public.vulns          SET severity = 'info' WHERE severity = 'recon';
UPDATE public.recon_findings SET severity = 'info' WHERE severity = 'recon';
UPDATE public.attack_vectors SET severity = 'info' WHERE severity = 'recon';

-- Any other table that grew a severity column since. Named tables above are
-- kept explicit for reviewability; this catches the rest rather than leaving a
-- silent gap when a new findings table appears.
DO $RECON$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT c.table_name
          FROM information_schema.columns c
          JOIN information_schema.tables tb
            ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
         WHERE c.table_schema = 'public'
           AND c.column_name = 'severity'
           AND tb.table_type = 'BASE TABLE'
           AND c.is_generated = 'NEVER'
           AND c.table_name NOT IN ('web_findings','vulns','recon_findings','attack_vectors')
    LOOP
        EXECUTE format(
            'UPDATE public.%I SET severity = %L WHERE severity = %L', t, 'info', 'recon');
    END LOOP;
END $RECON$;


CREATE INDEX IF NOT EXISTS idx_web_findings_infra_fp
    ON public.web_findings(infrastructure_fingerprint)
 WHERE infrastructure_fingerprint IS NOT NULL;

-- Group-level triage. Sparse on purpose: a row exists only once someone has
-- actually triaged the group, so this does not shadow the per-finding
-- workflow_status for the untouched majority.
CREATE TABLE IF NOT EXISTS public.finding_group_state (
    infrastructure_fingerprint text PRIMARY KEY,
    status          text DEFAULT 'new',
    assigned_to     text,
    notes           text,
    suppressed      boolean DEFAULT false,
    created_at      timestamptz DEFAULT now(),
    updated_at      timestamptz DEFAULT now()
);

CREATE OR REPLACE FUNCTION public._touch_finding_group_state() RETURNS trigger AS $fn$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_finding_group_state_updated_at ON public.finding_group_state;
CREATE TRIGGER trg_finding_group_state_updated_at
    BEFORE UPDATE ON public.finding_group_state
    FOR EACH ROW EXECUTE FUNCTION public._touch_finding_group_state();

-- Compute the key on write. The IP comes from the finding's asset, so this
-- resolves through assets rather than parsing it back out of the URL: after the
-- vhost normalisation, several asset rows share one ip, which is exactly the
-- relation being grouped on.
CREATE OR REPLACE FUNCTION public._web_findings_infra_fp() RETURNS trigger AS $fn$
DECLARE
    v_ip   text;
    v_port text;
BEGIN
    IF NEW.infrastructure_fingerprint IS NOT NULL THEN
        RETURN NEW;
    END IF;

    SELECT host(a.ip) INTO v_ip FROM public.assets a WHERE a.id = NEW.asset_id;

    -- No host means "same host" is unanswerable, and a blank name AND blank
    -- issue_type means this is not a finding (katana crawl rows look like that:
    -- 746 of 779 in one deployment). Either way, leave it ungrouped rather than
    -- inventing a bucket.
    IF v_ip IS NULL OR v_ip = ''
       OR (coalesce(btrim(NEW.name), '') = '' AND coalesce(btrim(NEW.issue_type), '') = '')
    THEN
        RETURN NEW;
    END IF;

    v_port := CASE WHEN NEW.port IS NOT NULL AND NEW.port <> 0
                   THEN NEW.port::text ELSE '0' END;

    NEW.infrastructure_fingerprint := md5('infra|' || v_ip || '|' || v_port
        || '|' || lower(btrim(coalesce(NEW.name, '')))
        || '|' || lower(btrim(coalesce(NEW.issue_type, ''))));
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

-- The name is deliberately "z_infra" so it sorts LAST. Postgres fires BEFORE
-- triggers in alphabetical order by trigger name, and this one depends on two
-- earlier ones:
--
--   trg_web_findings_dedup  -> RETURNs NULL for a duplicate, so a skipped
--                              INSERT never bothers computing a grouping key
--   trg_web_findings_port   -> populates NEW.port from the URL
--
-- Named trg_web_findings_infra it would fire at 'i', BEFORE 'port', and key on
-- port 0 while the stored row ended up with 443 — a wrong grouping key that
-- also disagrees with etl/fingerprint.py, which receives the real port.
DROP TRIGGER IF EXISTS trg_web_findings_infra ON public.web_findings;
DROP TRIGGER IF EXISTS trg_web_findings_z_infra ON public.web_findings;
CREATE TRIGGER trg_web_findings_z_infra
    BEFORE INSERT ON public.web_findings
    FOR EACH ROW EXECUTE FUNCTION public._web_findings_infra_fp();

-- Backfill through the same expression.
UPDATE public.web_findings w
   SET infrastructure_fingerprint = md5('infra|' || host(a.ip) || '|'
       || CASE WHEN w.port IS NOT NULL AND w.port <> 0 THEN w.port::text ELSE '0' END
       || '|' || lower(btrim(coalesce(w.name, '')))
       || '|' || lower(btrim(coalesce(w.issue_type, ''))))
  FROM public.assets a
 WHERE a.id = w.asset_id
   AND w.infrastructure_fingerprint IS NULL
   AND NOT (coalesce(btrim(w.name), '') = '' AND coalesce(btrim(w.issue_type), '') = '');

-- One row per underlying problem, with the vhosts it affects. A view rather
-- than a table so there is no member count to keep in sync — the per-vhost rows
-- remain the single source of truth.
CREATE OR REPLACE VIEW public.v_infrastructure_findings AS
SELECT
    w.infrastructure_fingerprint,
    min(host(a.ip))                                   AS ip,
    min(w.port)                                       AS port,
    min(w.name)                                       AS name,
    min(w.issue_type)                                 AS issue_type,
    -- WORST severity, not the lexically largest. max() on text ranks
    -- 'medium' above 'critical' and 'high', so a group that mixes them
    -- under-reported its own severity — silently, and in the dangerous
    -- direction. Every group in this deployment happened to be
    -- single-severity, so nothing showed it. public.severity_rank() is
    -- the one scale the whole stack shares.
    (array_agg(w.severity ORDER BY public.severity_rank(w.severity) DESC,
                                   w.severity))[1]     AS severity,
    count(*)                                          AS finding_count,
    count(DISTINCT a.id)                              AS affected_asset_count,
    array_agg(DISTINCT coalesce(a.hostname, host(a.ip))
              ORDER BY coalesce(a.hostname, host(a.ip))) AS affected_hosts,
    min(w.first_seen)                                 AS first_seen,
    max(w.last_seen)                                  AS last_seen,
    coalesce(s.status, 'new')                         AS group_status,
    s.assigned_to                                     AS group_assigned_to,
    coalesce(s.suppressed, false)                     AS group_suppressed
FROM public.web_findings w
JOIN public.assets a ON a.id = w.asset_id
LEFT JOIN public.finding_group_state s
       ON s.infrastructure_fingerprint = w.infrastructure_fingerprint
WHERE w.infrastructure_fingerprint IS NOT NULL
GROUP BY w.infrastructure_fingerprint, s.status, s.assigned_to, s.suppressed;



-- Dedup trigger for web_findings (see ensure_all_tables.sql for rationale).
CREATE OR REPLACE FUNCTION public.web_findings_dedup() RETURNS trigger AS $fn$
DECLARE
    existing_id uuid;
BEGIN
    -- Must match etl/fingerprint.py::web_fingerprint exactly, or a row inserted
    -- by a Python-side writer and one inserted here would not recognise each
    -- other as the same finding.
    IF NEW.fingerprint IS NULL THEN
        NEW.fingerprint := md5('web|' || rtrim(lower(btrim(coalesce(NEW.url, ''))), '/')
                                || '|' || lower(btrim(coalesce(NEW.name, '')))
                                || '|' || lower(btrim(coalesce(NEW.issue_type, ''))));
    END IF;

    SELECT id INTO existing_id
      FROM public.web_findings
     WHERE fingerprint = NEW.fingerprint;

    IF FOUND THEN
        -- Re-seeing a finding is new information about WHEN, not a new finding.
        UPDATE public.web_findings
           SET last_seen   = now(),
               severity    = COALESCE(NEW.severity, severity),
               evidence    = COALESCE(NEW.evidence, evidence),
               status_code = COALESCE(NEW.status_code, status_code)
         WHERE id = existing_id;
        RETURN NULL;   -- skip the INSERT
    END IF;

    IF NEW.first_seen IS NULL THEN NEW.first_seen := now(); END IF;
    IF NEW.last_seen  IS NULL THEN NEW.last_seen  := now(); END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_web_findings_dedup ON public.web_findings;
CREATE TRIGGER trg_web_findings_dedup
    BEFORE INSERT ON public.web_findings
    FOR EACH ROW EXECUTE FUNCTION public.web_findings_dedup();

-- Dedup trigger for vulns (see ensure_all_tables.sql for rationale/limits).

-- vulns needs first_seen / last_seen for the delta view, the same way
-- web_findings already has them. updated_at cannot stand in: the
-- trg_vulns_updated_at trigger touches it on ANY write, so an operator adding
-- tester_notes is indistinguishable from a scan re-observing the finding.
-- Maintained by vulns_dedup() below.
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS first_seen timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE public.vulns ADD COLUMN IF NOT EXISTS last_seen  timestamptz DEFAULT now(); EXCEPTION WHEN OTHERS THEN NULL; END $$;
-- Backfill existing rows: created_at is when we first saw it, updated_at is the
-- best available proxy for the last sighting on rows that predate these columns.
UPDATE public.vulns SET first_seen = COALESCE(first_seen, created_at, now()) WHERE first_seen IS NULL;
UPDATE public.vulns SET last_seen  = COALESCE(last_seen, updated_at, created_at, now()) WHERE last_seen IS NULL;

CREATE OR REPLACE FUNCTION public.vulns_dedup() RETURNS trigger AS $fn$
DECLARE
    existing_id uuid;
    v_ip   text;
    v_port text;
    v_cve  text;
BEGIN
    IF NEW.fingerprint IS NULL THEN
        SELECT coalesce(host(a.ip), '') INTO v_ip
          FROM public.assets a WHERE a.id = NEW.asset_id;
        SELECT CASE WHEN p.port IS NOT NULL AND p.port <> 0 THEN p.port::text ELSE NULL END
          INTO v_port FROM public.ports p WHERE p.id = NEW.port_id;

        -- Fall back to metadata.port when port_id is not set. vuln_fingerprint
        -- hashes the port the SCANNER observed, which is often recorded in
        -- metadata even when no ports row was linked — e.g. nuclei's
        -- CVE-2011-2523 match on 6200. Using it takes this expression from
        -- reproducing 33 of 34 live fingerprints to 34 of 34.
        IF v_port IS NULL AND (NEW.metadata->>'port') ~ '^[0-9]+$'
           AND (NEW.metadata->>'port') <> '0' THEN
            v_port := NEW.metadata->>'port';
        END IF;

        v_ip   := coalesce(v_ip, '');
        v_port := coalesce(v_port, '0');

        -- Mirrors _extract_first_cve: first array element matching the CVE
        -- shape, upper-cased. unnest preserves array order.
        SELECT upper(c) INTO v_cve
          FROM unnest(coalesce(NEW.cve, ARRAY[]::text[])) c
         WHERE c ~* '^CVE-[0-9]{4}-[0-9]+'
         LIMIT 1;

        IF v_cve IS NOT NULL THEN
            NEW.fingerprint := md5('cve|' || v_cve || '|' || v_ip || '|' || v_port);
        ELSE
            -- _normalize_script is strip().lower()
            NEW.fingerprint := md5('script|' || lower(btrim(coalesce(NEW.script, '')))
                                   || '|' || v_ip || '|' || v_port);
        END IF;
    END IF;

    SELECT id INTO existing_id
      FROM public.vulns WHERE fingerprint = NEW.fingerprint;

    IF FOUND THEN
        -- Re-seeing a vuln is new information about WHEN, not a new finding.
        --
        -- last_seen is maintained separately from updated_at on purpose:
        -- trg_vulns_updated_at touches updated_at on ANY write, including an
        -- operator editing tester_notes or workflow_status, so updated_at
        -- cannot answer "when did a scan last observe this". The delta view
        -- needs the scan-observation timestamp, which is this one.
        UPDATE public.vulns
           SET updated_at = now(),
               last_seen  = now(),
               severity   = COALESCE(NEW.severity, severity),
               output     = COALESCE(NEW.output, output),
               cvss       = COALESCE(NEW.cvss, cvss)
         WHERE id = existing_id;
        RETURN NULL;   -- skip the INSERT
    END IF;

    IF NEW.first_seen IS NULL THEN NEW.first_seen := now(); END IF;
    IF NEW.last_seen  IS NULL THEN NEW.last_seen  := now(); END IF;
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_vulns_dedup ON public.vulns;
CREATE TRIGGER trg_vulns_dedup
    BEFORE INSERT ON public.vulns
    FOR EACH ROW EXECUTE FUNCTION public.vulns_dedup();

-- recon_findings dedup (see ensure_all_tables.sql for the data-key rationale).
CREATE UNIQUE INDEX IF NOT EXISTS uq_recon_findings_fingerprint
    ON public.recon_findings(fingerprint);

CREATE OR REPLACE FUNCTION public.recon_findings_dedup() RETURNS trigger AS $fn$
DECLARE
    existing_id uuid;
BEGIN
    IF NEW.fingerprint IS NULL THEN
        NEW.fingerprint := md5('recon|' || lower(btrim(coalesce(NEW.source, '')))
                                || '|' || lower(btrim(coalesce(NEW.finding_type, '')))
                                || '|' || lower(btrim(coalesce(NEW.target, '')))
                                || '|' || lower(btrim(coalesce(NEW.data::text, ''))));
    END IF;

    SELECT id INTO existing_id
      FROM public.recon_findings WHERE fingerprint = NEW.fingerprint;

    IF FOUND THEN
        UPDATE public.recon_findings
           SET severity = COALESCE(NEW.severity, severity),
               data     = COALESCE(NEW.data, data)
         WHERE id = existing_id;
        RETURN NULL;   -- skip the INSERT
    END IF;

    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_recon_findings_dedup ON public.recon_findings;
CREATE TRIGGER trg_recon_findings_dedup
    BEFORE INSERT ON public.recon_findings
    FOR EACH ROW EXECUTE FUNCTION public.recon_findings_dedup();

-- ── raw_artifacts: complete, untruncated tool output ──────────────────────
--
-- Every byte a tool produced, kept verbatim for post-analysis and LLM
-- processing. This exists because the pipeline was lossy in three places at
-- once and each loss was invisible:
--
--   1. tool_executions.output is written ONLY by kali-listener. Output from
--      the scanner services and targeted_recon had no durable home at all.
--   2. When a tool writes its own JSON (nuclei -jsonl, whatweb --log-json,
--      enum4linux-ng -oJ, dnsrecon --json, sqlmap --report-json), that file
--      was read, POSTed to the parser, then UNLINKED — the authoritative
--      structured artifact was the one thing never persisted.
--   3. The parser keeps 8 KB of raw_output on a finding; ingest truncates at
--      200 KB. Fine for display, useless as a source of truth.
--
-- Content is deduped on (tool, target, sha256) rather than blindly appended:
-- re-running the same scan yields byte-identical output, and paying an LLM to
-- re-read it is pure waste. Repeats bump last_seen/occurrences, matching the
-- first_seen/last_seen convention used by the finding tables.
CREATE TABLE IF NOT EXISTS public.raw_artifacts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id    uuid,
    tool             text NOT NULL,
    command          text,
    target           text,
    port             integer,
    service          text,
    exec_id          uuid,
    job_id           text,
    scan_id          uuid,
    source           text DEFAULT 'unknown',
    content_format   text DEFAULT 'text',
    native_json      boolean DEFAULT false,
    content          text NOT NULL,
    content_sha256   text NOT NULL,
    byte_size        integer,
    first_seen       timestamptz DEFAULT now(),
    last_seen        timestamptz DEFAULT now(),
    occurrences      integer DEFAULT 1,
    -- LLM post-processing state. 'pending' is the work queue.
    llm_status       text DEFAULT 'pending',
    llm_model        text,
    llm_processed_at timestamptz,
    llm_result       jsonb,
    llm_error        text,
    llm_attempts     integer DEFAULT 0,
    created_at       timestamptz DEFAULT now(),
    CONSTRAINT raw_artifacts_llm_status_check CHECK (
        llm_status IN ('pending','processing','done','failed','skipped'))
);

ALTER TABLE public.raw_artifacts
    DROP CONSTRAINT IF EXISTS raw_artifacts_scan_id_fkey;
ALTER TABLE public.raw_artifacts
    ADD CONSTRAINT raw_artifacts_scan_id_fkey
    FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON DELETE SET NULL;

-- Required by the ON CONFLICT upsert in /ingest/raw-artifact. Without a
-- matching unique index that statement RAISES rather than deduping.
CREATE UNIQUE INDEX IF NOT EXISTS uq_raw_artifacts_identity
    ON public.raw_artifacts (tool, COALESCE(target,''), content_sha256);
-- The post-processing queue reads WHERE llm_status='pending' ORDER BY created_at.
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_llm_status
    ON public.raw_artifacts (llm_status, created_at);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_tool     ON public.raw_artifacts (tool);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_target   ON public.raw_artifacts (target);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_exec_id  ON public.raw_artifacts (exec_id);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_job_id   ON public.raw_artifacts (job_id);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_created  ON public.raw_artifacts (created_at DESC);
