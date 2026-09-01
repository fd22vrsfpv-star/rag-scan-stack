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
    -- What the recommendation is actually aimed at. Dispatch only understands
    -- 'service' — (ip, service, port) -> scanner. The others exist so a
    -- recommendation that does NOT fit that shape is refused with a reason
    -- instead of being fired at an IP as if it were a network scan:
    --   service   default; a network service on a host
    --   artifact  a FILE, not a host (exiftool on a downloaded document). Needs
    --             an artifact reference; `ip` is meaningless for it.
    --   range     a CIDR/scope swept once (masscan). Must be deduped at
    --             GENERATION, not per discovered service, or it produces N
    --             identical sweeps.
    --   resource  not runnable at all (seclists, wordlists) — an INPUT to other
    --             tools. Must never count against KB coverage, or the metric can
    --             never reach 100% by construction.
    target_kind text NOT NULL DEFAULT 'service'
                CHECK (target_kind IN ('service','artifact','range','resource')),
    executed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
-- Existing installs: add target_kind + its constraint without failing if present.
DO $$ BEGIN
    ALTER TABLE public.scan_recommendations
        ADD COLUMN IF NOT EXISTS target_kind text NOT NULL DEFAULT 'service';
EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN
    ALTER TABLE public.scan_recommendations
        ADD CONSTRAINT scan_recommendations_target_kind_check
        CHECK (target_kind IN ('service','artifact','range','resource'));
EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE INDEX IF NOT EXISTS idx_scan_recommendations_target_kind ON public.scan_recommendations(target_kind);
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

-- Migration: store the RECOVERED SECRET alongside the account it belongs to.
--
-- CAUTION: this column holds credential material IN PLAINTEXT. That is a
-- deliberate operator decision, not an oversight — a recovered password is the
-- primary artefact of a credential-testing phase and lateral movement needs the
-- actual secret, not a masked copy. Consequences to be aware of:
--
--   * /export/data includes the `credentials` category BY DEFAULT and reads
--     SELECT *, so JSON and CSV exports carry these passwords. That is the
--     point — the exports feed manual tools — but it means an export file is
--     as sensitive as the database.
--   * metadata.audit stays MASKED. It records every password TRIED, including
--     ones belonging to no account here, and unmasking a wordlist buys nothing.
--   * anyone with read access to this table has the credentials. Restrict it.
--
-- Named secret_value to pair with the existing secret_type, which already says
-- what KIND of secret this is (password, ntlm_hash, ssh_key, ...).
DO $$ BEGIN
  ALTER TABLE public.credential_findings ADD COLUMN IF NOT EXISTS secret_value text;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
COMMENT ON COLUMN public.credential_findings.secret_value IS
  'Recovered secret in PLAINTEXT (password/hash/key per secret_type). Present by '
  'operator decision so follow-on attacks can use it. Exported by /export/data.';

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
-- Links a raw_artifact (which carries job_id) to the findings its run produced,
-- for the Scan Results per-artifact summary (target + severity counts).
CREATE INDEX IF NOT EXISTS idx_recon_findings_job_id ON public.recon_findings ((data->>'job_id'));

-- ===============================
-- Playwright tables
-- ===============================

-- playwright_scans
CREATE TABLE IF NOT EXISTS public.playwright_scans (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id     uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    url          text NOT NULL,
    status       text NOT NULL DEFAULT 'queued'
                 CHECK (status IN ('queued','running','completed','failed','blocked')),
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

-- attack_path_edges (per-asset attack progression: technique -> technique
-- ordered by ATT&CK tactic position, plus credential-access lateral edges).
-- Built by compute_attack_vectors; feeds the Attack Map graph + path queries.
CREATE TABLE IF NOT EXISTS public.attack_path_edges (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id uuid,
    asset_id      uuid REFERENCES public.assets(id) ON DELETE CASCADE,
    target        text,
    from_technique text NOT NULL,
    to_technique   text NOT NULL,
    edge_type     text NOT NULL DEFAULT 'enables',  -- enables | lateral | cred_access
    weight        numeric NOT NULL DEFAULT 0,        -- combined risk 0..100
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (target, from_technique, to_technique, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_attack_path_edges_engagement ON public.attack_path_edges(engagement_id);
CREATE INDEX IF NOT EXISTS idx_attack_path_edges_asset ON public.attack_path_edges(asset_id);

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
                       CHECK (status IN ('active','completed','failed','stopped','stalled','awaiting_approval')),
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

-- ---------------------------------------------------------------------------
-- LangGraph durable checkpoints (AGENT_ENGINE=langgraph)
--
-- Library-managed by langgraph-checkpoint-postgres (PostgresSaver.setup(), run
-- on every langgraph session start/resume). Declared here so a fresh install
-- has them up front and the health check can assert them. DDL copied verbatim
-- from langgraph.checkpoint.postgres.base.MIGRATIONS.
--
-- checkpoint_migrations is intentionally left EMPTY: the library reads MAX(v)
-- to decide what to apply, and every migration is idempotent, so an empty table
-- means "re-apply all" (correct). Seeding versions would make it SKIP work.
-- Mirrored in db_init/create_langgraph_checkpoint_tables.sql — keep in sync.
-- ---------------------------------------------------------------------------
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

CREATE INDEX IF NOT EXISTS checkpoints_thread_id_idx ON public.checkpoints(thread_id);
CREATE INDEX IF NOT EXISTS checkpoint_blobs_thread_id_idx ON public.checkpoint_blobs(thread_id);
CREATE INDEX IF NOT EXISTS checkpoint_writes_thread_id_idx ON public.checkpoint_writes(thread_id);

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

-- One row per (session, job). REQUIRED by the upsert in
-- autogen_agents/scan_tools.py::persist_to_db.
--
-- The table's only key was PRIMARY KEY (id), so the existing
-- `ON CONFLICT DO NOTHING` had no constraint to match and never fired: every
-- persist re-INSERTED. A live database held 104 rows for 75 distinct jobs,
-- including one job with 6 copies carrying two different statuses.
--
-- It also made a scan persisted while `running` impossible to correct once it
-- completed, which is what stops session_scan_metrics being a usable source for
-- rebuilding a flow summary after the in-memory registry is discarded.
--
-- Deduplicate before creating the index or it cannot be built. Keep the most
-- advanced row per job: a terminal status beats `running`, then the most recent.
DELETE FROM public.session_scan_metrics a
 USING public.session_scan_metrics b
 WHERE a.job_id IS NOT NULL
   AND a.session_id = b.session_id
   AND a.job_id     = b.job_id
   AND a.id <> b.id
   -- id is the final tiebreaker so the ordering is STRICT and total. Without it
   -- two rows with the same status rank and the same timestamp would each fail
   -- the "<" test, both survive, and CREATE UNIQUE INDEX would then error out.
   AND (
         (CASE WHEN a.status IN ('running','queued') THEN 0 ELSE 1 END,
          COALESCE(a.completed_at, a.started_at, a.created_at), a.id)
         <
         (CASE WHEN b.status IN ('running','queued') THEN 0 ELSE 1 END,
          COALESCE(b.completed_at, b.started_at, b.created_at), b.id)
       );

CREATE UNIQUE INDEX IF NOT EXISTS uq_session_scan_metrics_session_job
    ON public.session_scan_metrics(session_id, job_id);

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
    source             text NOT NULL CHECK (source IN ('exploitdb', 'metasploit', 'webshell')),
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

-- ============================================================================
-- Security tests — reusable, re-runnable proof-of-exploitability records.
-- ============================================================================
-- security_tests is the TEST DEFINITION (a command + the assertion that proves
-- it, tiered safe|impactful); security_test_runs is the append-only pass/fail
-- HISTORY. This is a thin scheduling/assertion layer over machinery that already
-- exists — it does NOT re-implement exploit execution:
--   * an IMPACTFUL test references a pending_exploits row (its command + the
--     approval gate live there) and each run maps to an exploit_results row;
--   * a SAFE test carries its own command and each run maps to a tool_executions
--     row (written by kali-listener /tools/execute).
-- ── Credential-reuse (spray) attempt ledger ─────────────────────────────────
-- Tracks which (credential, target) pairs the reuse loop has already sprayed so
-- it never re-sprays. No such dedup existed; credential_findings tracks
-- SUCCESSES, not attempts. secret_fingerprint is a sha256 of the secret so the
-- plaintext is not duplicated here.
CREATE TABLE IF NOT EXISTS public.credential_spray_attempts (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id        uuid,
    username             text NOT NULL,
    secret_fingerprint   text,
    target_host          text NOT NULL,
    target_port          integer NOT NULL,
    service              text,
    source_credential_id uuid,
    status               text NOT NULL DEFAULT 'dispatched',  -- dispatched|skipped|failed
    brutus_job_id        text,
    attempted_at         timestamptz NOT NULL DEFAULT now()
);
-- COALESCE the nullable secret so a NULL fingerprint does not bypass dedup
-- (a table-level UNIQUE can't hold an expression; a unique index can).
CREATE UNIQUE INDEX IF NOT EXISTS uq_spray_identity ON public.credential_spray_attempts
    (username, COALESCE(secret_fingerprint, ''), target_host, target_port);
CREATE INDEX IF NOT EXISTS idx_spray_engagement ON public.credential_spray_attempts(engagement_id);

-- Discovered or operator-set password/lockout policy. Caps how many times a
-- single account may be sprayed in a window so the loop never locks a real
-- account. When absent, the reuse loop uses a conservative built-in default.
CREATE TABLE IF NOT EXISTS public.password_policies (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id     uuid,
    scope_host        text,            -- host/domain (NULL = engagement-wide)
    lockout_threshold integer,         -- failed attempts before lockout
    window_minutes    integer NOT NULL DEFAULT 30,
    source            text NOT NULL DEFAULT 'operator',
    updated_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pwpolicy_engagement ON public.password_policies(engagement_id);

-- Per (account, service) approval to spray a credential. With require_approval
-- on (default), a spray to an (account, service) pair with no approval is held.
CREATE TABLE IF NOT EXISTS public.credential_spray_approvals (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id uuid,
    username      text NOT NULL,
    service       text NOT NULL,
    approved      boolean NOT NULL DEFAULT true,
    approved_by   text,
    note          text,
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_spray_approval ON public.credential_spray_approvals
    (COALESCE(engagement_id::text,''), lower(username), lower(service));

-- ── Lateral-movement attack-path ledger ─────────────────────────────────────
-- Records each hop the platform takes with a harvested credential: from the
-- host we looted it on, via an account, to another in-scope host/service. Built
-- for the report ("how we got from A to D") and to bound/loop-guard chaining.
-- Every hop is still gated by the scope gate + spray approval at dispatch time;
-- this table is the record, not the authority.
CREATE TABLE IF NOT EXISTS public.lateral_movement (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id uuid,
    from_host     text,             -- where the credential was harvested
    via_username  text NOT NULL,
    to_host       text NOT NULL,
    to_service    text,
    to_port       integer,
    hop           integer NOT NULL DEFAULT 1,
    status        text NOT NULL DEFAULT 'planned',  -- planned|dispatched|succeeded|failed
    source_credential_id uuid,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_lateral_engagement ON public.lateral_movement(engagement_id);

-- ── Global kill-switch / blast-radius control ───────────────────────────────
-- One row per control scope: 'global' halts EVERY dispatch; an engagement_id
-- string halts only that engagement. Enforced at the scope gate
-- (etl/scope_gate.is_halted -> load_dispatch_scope returns ([], "halted")), so a
-- halt refuses every gated dispatcher with no per-caller change. Also read by
-- the recon-agent loop and the /pentest launcher for a clear "halted" message.
CREATE TABLE IF NOT EXISTS public.platform_control (
    scope        text PRIMARY KEY,               -- 'global' | '<engagement_id>'
    halted       boolean NOT NULL DEFAULT false,
    reason       text,
    actor        text,
    -- Blast-radius budget (nullable = no cap). Enforced alongside the halt.
    scan_budget       integer,                    -- max dispatches for this scope
    scans_used        integer NOT NULL DEFAULT 0,
    host_cap          integer,                    -- max distinct hosts touched
    metadata     jsonb NOT NULL DEFAULT '{}',
    updated_at   timestamptz NOT NULL DEFAULT now()
);
-- The singleton global row always exists (not halted by default).
INSERT INTO public.platform_control (scope, halted)
VALUES ('global', false)
ON CONFLICT (scope) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.security_tests (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL,
    description           text,
    tier                  text NOT NULL DEFAULT 'safe'
                          CHECK (tier IN ('safe','impactful')),
    -- free text on purpose (mirrors pending_exploits.exploit_type vocabulary);
    -- a new category never needs a CHECK migration.
    category              text,
    target_ip             inet,
    target_host           text,
    target_port           integer,
    target_service        text,
    -- SAFE lane command; NULL for impactful (the command lives on the
    -- referenced pending_exploit).
    command               text,
    tool                  text,
    -- Structured assertion, evaluated deterministically by record_test_run.
    assertion             jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_finding_source text,
    source_finding_id     uuid,
    attack_vector_id      uuid REFERENCES public.attack_vectors(id) ON DELETE SET NULL,
    pending_exploit_id    uuid REFERENCES public.pending_exploits(id) ON DELETE SET NULL,
    created_by_session    uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
    engagement_id         uuid REFERENCES public.engagements(id) ON DELETE SET NULL,
    enabled               boolean NOT NULL DEFAULT true,
    -- Latest-run rollup for cheap list rendering (updated by record_test_run).
    last_run_at           timestamptz,
    last_run_status       text CHECK (last_run_status IN ('pass','fail','error','skipped')),
    run_count             integer NOT NULL DEFAULT 0,
    metadata              jsonb DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    -- An impactful test MUST reference a pending_exploit (its command + approval
    -- gate); a safe test MUST carry its own command.
    CONSTRAINT security_tests_lane_ck CHECK (
        (tier = 'impactful' AND pending_exploit_id IS NOT NULL)
        OR (tier = 'safe' AND command IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_security_tests_session    ON public.security_tests(created_by_session);
CREATE INDEX IF NOT EXISTS idx_security_tests_engagement ON public.security_tests(engagement_id) WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_tests_target     ON public.security_tests(target_ip, target_port);
CREATE INDEX IF NOT EXISTS idx_security_tests_tier       ON public.security_tests(tier);
CREATE INDEX IF NOT EXISTS idx_security_tests_pending    ON public.security_tests(pending_exploit_id) WHERE pending_exploit_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_tests_enabled    ON public.security_tests(enabled) WHERE enabled;

CREATE TABLE IF NOT EXISTS public.security_test_runs (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id              uuid NOT NULL REFERENCES public.security_tests(id) ON DELETE CASCADE,
    ran_at               timestamptz NOT NULL DEFAULT now(),
    completed_at         timestamptz,
    duration_ms          integer,
    status               text NOT NULL DEFAULT 'error'
                         CHECK (status IN ('pass','fail','error','skipped')),
    lane                 text NOT NULL CHECK (lane IN ('safe','impactful')),
    command_run          text,
    exit_code            integer,
    result_summary       text,
    assertion_eval       jsonb DEFAULT '{}'::jsonb,
    -- Exactly one is set per lane (enforced in record_test_run).
    tool_execution_id    uuid REFERENCES public.tool_executions(id) ON DELETE SET NULL,
    exploit_result_id    uuid REFERENCES public.exploit_results(id) ON DELETE SET NULL,
    triggered_by         text,
    triggered_by_session uuid REFERENCES public.agent_sessions(id) ON DELETE SET NULL,
    engagement_id        uuid REFERENCES public.engagements(id) ON DELETE SET NULL,
    output               text,
    metadata             jsonb DEFAULT '{}'::jsonb,
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_security_test_runs_test       ON public.security_test_runs(test_id, ran_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_test_runs_status     ON public.security_test_runs(status);
CREATE INDEX IF NOT EXISTS idx_security_test_runs_engagement ON public.security_test_runs(engagement_id) WHERE engagement_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_test_runs_toolexec   ON public.security_test_runs(tool_execution_id) WHERE tool_execution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_test_runs_exploitres ON public.security_test_runs(exploit_result_id) WHERE exploit_result_id IS NOT NULL;

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

DO $$ BEGIN IF to_regclass('public.security_tests') IS NOT NULL THEN
  DROP TRIGGER IF EXISTS trg_security_tests_updated_at ON public.security_tests;
  CREATE TRIGGER trg_security_tests_updated_at BEFORE UPDATE ON public.security_tests FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();
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
    entity_type    text NOT NULL CHECK (entity_type IN ('finding','web_finding','playwright_finding','asset','checklist_item','exploit_result','security_test_run')),
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

-- Self-adapting extractor overlay. When the LLM analysis pass extracts something
-- a tool's deterministic profile (knowledge/extractors/{tool}.yaml) missed, the
-- distiller (app/rag-api/extractor_learn.py) authors a stable regex ONCE and
-- stores it here; extractor_specs.load_specs() merges ACTIVE rows onto the tool's
-- spec so future runs extract it deterministically — no model. 'deterministic'
-- rows auto-apply (read-only); 'notable'/'follow_on' rows start 'proposed' and
-- fire only once approved. POST /extractors/export writes approved rows to YAML.
CREATE TABLE IF NOT EXISTS public.extractor_learned (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tool              text NOT NULL,
    kind              text NOT NULL CHECK (kind IN ('deterministic','notable','follow_on')),
    rule              jsonb NOT NULL,
    status            text NOT NULL DEFAULT 'proposed'
                      CHECK (status IN ('active','proposed','rejected')),
    confidence        numeric,
    source            text NOT NULL DEFAULT 'distilled',
    sample_artifact_id uuid,
    reviewed_by       text,               -- audit: who approved/rejected
    created_at        timestamptz DEFAULT now(),
    updated_at        timestamptz DEFAULT now(),
    approved_at       timestamptz
);
-- One learned rule per (tool, kind, rule shape) — re-distilling the same shape
-- is a no-op rather than a duplicate.
CREATE UNIQUE INDEX IF NOT EXISTS ux_extractor_learned_tool_kind_rule
  ON public.extractor_learned (tool, kind, md5(rule::text));
CREATE INDEX IF NOT EXISTS idx_extractor_learned_tool_status
  ON public.extractor_learned (tool, status);
DROP TRIGGER IF EXISTS trg_extractor_learned_updated ON public.extractor_learned;
CREATE TRIGGER trg_extractor_learned_updated
  BEFORE UPDATE ON public.extractor_learned
  FOR EACH ROW EXECUTE FUNCTION public._touch_updated_at();

-- Agent-to-agent feedback channel. One agent flags something interesting (a
-- finding worth another run, a coverage gap); a coordinator turns approved flags
-- into scan_recommendations (which the recon agent dispatches through the scope
-- gate). See app/rag-api/agent_flags.py.
CREATE TABLE IF NOT EXISTS public.agent_flags (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    flagging_agent  text NOT NULL,
    target_agent    text,
    engagement_id   uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    flag_type       text NOT NULL
                    CHECK (flag_type IN ('interesting_finding','needs_rescan','coverage_gap')),
    data            jsonb NOT NULL DEFAULT '{}'::jsonb,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','acknowledged','acted','dismissed')),
    acted_by        text,               -- audit: who approved/dismissed
    created_at      timestamptz DEFAULT now(),
    acted_at        timestamptz
);
CREATE INDEX IF NOT EXISTS idx_agent_flags_status ON public.agent_flags (status);
CREATE INDEX IF NOT EXISTS idx_agent_flags_engagement ON public.agent_flags (engagement_id);

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

-- post_review_reports — review of work that RAN (see app/rag-api/post_review_agent.py)
--
-- engagement_id is NULLABLE here, unlike gap_analysis_reports: tool_executions
-- carries no engagement_id column, so a review is stack-wide by default. Making
-- it NOT NULL would force a false attribution onto every stored report.
CREATE TABLE IF NOT EXISTS public.post_review_reports (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id       uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    status              text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    report              jsonb NOT NULL DEFAULT '{}',
    executions_reviewed integer NOT NULL DEFAULT 0,
    issues_found        integer NOT NULL DEFAULT 0,
    reruns_queued       integer NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz,
    triggered_by        text DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_post_review_created ON post_review_reports(created_at DESC);

-- wordlists.path is the real identity of a list; `name` (already UNIQUE) is only
-- its basename, and seclists ships the same basename in several directories.
-- Without this index, POST /wordlists/discover's ON CONFLICT (path) raises
-- "no unique or exclusion constraint matching the ON CONFLICT specification".
CREATE UNIQUE INDEX IF NOT EXISTS ux_wordlists_path ON public.wordlists(path);

-- v_identity_credential_state — "which discovered accounts have no password yet"
--
-- DERIVED, never stored. A stored `has_credential` flag goes stale the moment a
-- password is cracked or a spray succeeds, and a stale flag here would send the
-- operator to re-attack an account already owned — or skip one still open.
--
-- `identities.status` is an ACCOUNT-state field (active/disabled/unknown/deleted)
-- and cannot express credential knowledge, which is why this is a separate axis:
--   status='unknown' + no credential  -> enumerated only, never authenticated
--   status='active'  + credential     -> a login that worked
--
-- Matching is on username AND host, because a username is only meaningful with
-- the host it was enumerated on. `identities.domain` holds that host for locally
-- discovered principals (the bridge writes `user@host` into identifier and the
-- host into domain).
CREATE OR REPLACE VIEW public.v_identity_credential_state AS
SELECT i.id                AS identity_id,
       i.provider,
       i.identifier,
       i.display_name      AS username,
       i.domain            AS host,
       i.principal_type,
       i.status,
       i.sources,
       i.tags,
       i.first_seen,
       i.last_seen,
       COALESCE(cv.n, 0)   AS vault_entries,
       COALESCE(cf.n, 0)   AS verified_findings,
       (COALESCE(cv.n, 0) + COALESCE(cf.n, 0)) > 0 AS has_credential,
       CASE
         WHEN COALESCE(cf.n, 0) > 0 THEN 'password_verified'
         WHEN COALESCE(cv.n, 0) > 0 THEN 'password_stored'
         ELSE 'username_only'
       END                 AS credential_state
  FROM public.identities i
  LEFT JOIN (
        SELECT lower(btrim(username)) AS u, count(*) AS n
          FROM public.credential_vault
         WHERE COALESCE(username, '') <> ''
           AND COALESCE(credential_value, cracked_value, '') <> ''
         GROUP BY 1
  ) cv ON cv.u = lower(btrim(i.display_name))
  LEFT JOIN (
        SELECT lower(btrim(username)) AS u, host(ip) AS h, count(*) AS n
          FROM public.credential_findings
         WHERE COALESCE(username, '') <> ''
         GROUP BY 1, 2
  ) cf ON cf.u = lower(btrim(i.display_name))
      AND cf.h = i.domain;

CREATE INDEX IF NOT EXISTS idx_identities_domain ON public.identities(domain)
    WHERE domain IS NOT NULL;

-- scan_parameters — values the OPERATOR declares, and nothing else.
--
-- Discovered values are NOT stored here. They live in recon_findings with their
-- provenance and history, and are read from there; copying them into a table
-- would go stale the moment a re-scan disagrees, which is the same trap avoided
-- with v_identity_credential_state.
--
-- This table holds only what no tool can discover: "treat the lockout as 5",
-- "never spray this host", "assume 20 attempts a minute". The effective value a
-- scan should use is `declared if present, else observed, else the default in
-- knowledge/scan_parameters.yaml` — resolved in app/rag-api/scan_parameters.py
-- rather than duplicated into SQL, so the vocabulary lives in exactly one place.
CREATE TABLE IF NOT EXISTS public.scan_parameters (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_type   text NOT NULL DEFAULT 'host'
                 CHECK (scope_type IN ('global', 'host', 'service')),
    -- '' for global, so the unique index constrains it: a NULL here would let
    -- unlimited duplicate global declarations through.
    scope_value  text NOT NULL DEFAULT '',
    key          text NOT NULL,
    value        text,
    note         text,
    declared_by  text,
    engagement_id uuid REFERENCES public.engagements(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_scan_parameters_scope_key
    ON public.scan_parameters(scope_type, scope_value, key);
CREATE INDEX IF NOT EXISTS idx_scan_parameters_key ON public.scan_parameters(key);
CREATE INDEX IF NOT EXISTS idx_post_review_engagement ON post_review_reports(engagement_id)
    WHERE engagement_id IS NOT NULL;

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
-- TIER 24: Per-service / per-port prompts + RAG training data
-- ============================================================================
-- Kept in sync with db_init/add_service_prompts.sql (the standalone migration
-- for existing installs). Any change here must be mirrored there.

-- Operator-authored guidance injected into the LLM's tool-selection prompt
-- whenever a matching service/port is discovered.
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
    -- Enforce that selector columns match the declared selector_type, so a row
    -- can never be silently unreachable by the resolver.
    CONSTRAINT service_prompts_selector_shape CHECK (
        (selector_type = 'service'      AND service IS NOT NULL AND port IS NULL     AND tech IS NULL)
     OR (selector_type = 'port'         AND port    IS NOT NULL AND service IS NULL  AND tech IS NULL)
     OR (selector_type = 'port_service' AND port    IS NOT NULL AND service IS NOT NULL AND tech IS NULL)
     OR (selector_type = 'tech'         AND tech    IS NOT NULL AND service IS NULL  AND port IS NULL)
    )
);

-- Converge installs created before the 'tech' selector existed.
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

-- COALESCE keeps NULLs from defeating uniqueness — in Postgres NULL <> NULL,
-- so a plain UNIQUE would allow unlimited duplicate global rules.
-- `tech` MUST be in the key: for selector_type='tech' service and port are
-- both NULL, so without it every tech rule collapses onto one index entry.
DROP INDEX IF EXISTS idx_service_prompts_selector;
CREATE UNIQUE INDEX IF NOT EXISTS idx_service_prompts_selector
    ON public.service_prompts (
        selector_type,
        COALESCE(service, ''),
        COALESCE(tech, ''),
        COALESCE(port, -1),
        COALESCE(engagement_id, '00000000-0000-0000-0000-000000000000'::uuid)
    );
CREATE INDEX IF NOT EXISTS idx_service_prompts_tech
    ON public.service_prompts (lower(tech)) WHERE tech IS NOT NULL;

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

-- exploit_chunks: service/port scoping so training documents can be retrieved
-- per service or port. Nullable — every existing ExploitDB and playbook row
-- keeps working unchanged; retrieval only filters when a service is supplied.
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS service  text;
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS port     integer;
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS doc_kind text;
ALTER TABLE public.exploit_chunks ADD COLUMN IF NOT EXISTS tech     text;

CREATE INDEX IF NOT EXISTS idx_exploit_chunks_service
    ON public.exploit_chunks (lower(service)) WHERE service IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_port
    ON public.exploit_chunks (port) WHERE port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_doc_kind
    ON public.exploit_chunks (doc_kind) WHERE doc_kind IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exploit_chunks_tech
    ON public.exploit_chunks (lower(tech)) WHERE tech IS NOT NULL;

GRANT ALL PRIVILEGES ON public.service_prompts TO app;
DO $$ BEGIN
  GRANT ALL PRIVILEGES ON public.service_prompts TO scans;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

-- ============================================================================
-- Summary
-- ============================================================================
SELECT 'ensure_all_tables.sql complete — schema is ready' as status;
SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;

-- ===========================================================================
-- Finding deduplication: enforce the fingerprints that were already computed
-- ===========================================================================
--
-- CLAUDE.md requires "finding fingerprinting (stable hash) to deduplicate across
-- tools/runs" and "first seen / last seen". etl/fingerprint.py implements the
-- hashes, the tables carry fingerprint/first_seen/last_seen columns — and
-- nothing ever enforced them, so duplicates accumulated unchecked:
--
--     vulns                369 rows /    34 fingerprints   10.9x
--     web_findings/katana  32218 rows /   630 (url,name)   51.1x
--     web_findings/zap     28232 rows / 27039 fingerprints  1.04x
--
-- ZAP was the only source computing a fingerprint at all, which is also why it
-- is the only one that is nearly clean — evidence the mechanism works as soon as
-- it is applied. Every other source wrote NULL, and NULLs never conflict, so no
-- index alone could have deduplicated them.
--
-- Order matters: backfill the missing fingerprints, collapse duplicates, and
-- only then add the unique index.

-- 1. Backfill web_findings.fingerprint for the ~54% of rows that never got one.
--
-- This MUST reproduce etl/fingerprint.py::web_fingerprint exactly, or the
-- backfilled rows will not match what the parsers generate and the same finding
-- will duplicate once more. That function is:
--     key = "web|" + url.strip().lower().rstrip("/") + "|" + name.strip().lower()
--           + "|" + issue_type.strip().lower()
-- Verified byte-for-byte against the Python for URL casing, surrounding
-- whitespace, repeated trailing slashes, and NULL fields.
UPDATE public.web_findings
   SET fingerprint = md5('web|' || rtrim(lower(btrim(coalesce(url, ''))), '/')
                          || '|' || lower(btrim(coalesce(name, '')))
                          || '|' || lower(btrim(coalesce(issue_type, ''))))
 WHERE fingerprint IS NULL;

-- 2. Collapse duplicates, preserving the real first/last seen window.
--    Aggregate BEFORE deleting: the surviving row must span the whole group,
--    otherwise collapsing rows silently narrows a finding's observed lifetime.
UPDATE public.web_findings w
   SET first_seen = g.min_first,
       last_seen  = g.max_last
  FROM (SELECT fingerprint,
               min(coalesce(first_seen, created_at)) AS min_first,
               max(coalesce(last_seen,  created_at)) AS max_last
          FROM public.web_findings
         WHERE fingerprint IS NOT NULL
         GROUP BY fingerprint HAVING count(*) > 1) g
 WHERE w.fingerprint = g.fingerprint;

DELETE FROM public.web_findings a
 USING public.web_findings b
 WHERE a.fingerprint IS NOT NULL
   AND a.fingerprint = b.fingerprint
   AND a.id <> b.id
   -- Keep the most recently seen row; id is the final tiebreaker so the
   -- ordering is strict and total and exactly one row per group survives.
   AND (coalesce(a.last_seen, a.created_at), a.id)
       < (coalesce(b.last_seen, b.created_at), b.id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_web_findings_fingerprint
    ON public.web_findings(fingerprint);

-- 3. Same for vulns. Every row already carries a fingerprint here, so there is
--    nothing to backfill — only 10.9x of accumulated duplication to collapse.
DELETE FROM public.vulns a
 USING public.vulns b
 WHERE a.fingerprint IS NOT NULL
   AND a.fingerprint = b.fingerprint
   AND a.id <> b.id
   AND (coalesce(a.updated_at, a.created_at), a.id)
       < (coalesce(b.updated_at, b.created_at), b.id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_vulns_fingerprint
    ON public.vulns(fingerprint);

-- credential_findings: one row per (ip, port, username, auth_type).
--
-- Same class as the fingerprint problem above, but this table has no
-- fingerprint column — its natural key is the account itself. Re-testing the
-- same credential re-inserted every time: 22 rows for 7 real credentials, and
-- the findings list showed "Valid credentials — anonymous@ftp:21" twice.
--
-- Re-verification is meaningful information, so the upsert advances
-- last_verified_at rather than ignoring the row. NULL usernames are excluded
-- from the key via a partial index; they carry no account identity to dedupe on.
-- Collapse duplicates on the COALESCED key before tightening the index.
--
-- The previous dedupe gated on `username IS NOT NULL`, which is dead: username
-- is NOT NULL in the schema. The actual hole was auth_type, which IS nullable —
-- and in Postgres a NULL makes rows non-equal for a unique index, so two rows
-- with the same (ip, port, username) and a NULL auth_type were both stored.
-- Demonstrated on this deployment: two identical inserts with auth_type NULL
-- both landed; with auth_type='password' the second was correctly rejected.
UPDATE public.credential_findings c
   SET last_verified_at = g.max_seen
  FROM (SELECT ip, port, username, COALESCE(auth_type, '') AS auth_key,
               max(coalesce(last_verified_at, discovered_at, created_at)) AS max_seen
          FROM public.credential_findings
         GROUP BY ip, port, username, COALESCE(auth_type, '')
        HAVING count(*) > 1) g
 WHERE c.ip = g.ip AND c.port = g.port AND c.username = g.username
   AND COALESCE(c.auth_type, '') = g.auth_key;

DELETE FROM public.credential_findings a
 USING public.credential_findings b
 WHERE a.ip = b.ip
   AND a.port = b.port
   AND a.username = b.username
   AND COALESCE(a.auth_type, '') = COALESCE(b.auth_type, '')
   AND a.id <> b.id
   -- Prefer a confirmed-valid row over a failed attempt for the same account,
   -- then the most recently seen; id makes the ordering strict.
   AND (coalesce(a.valid_cred, false),
        coalesce(a.last_verified_at, a.discovered_at, a.created_at), a.id)
       < (coalesce(b.valid_cred, false),
          coalesce(b.last_verified_at, b.discovered_at, b.created_at), b.id);

-- Total, not partial, and coalesced on the one nullable key column. Any
-- ON CONFLICT targeting this index must repeat the expression EXACTLY or
-- Postgres raises "no unique or exclusion constraint matching the ON CONFLICT
-- specification" on every row (see the comment in etl/asset_utils.py for what
-- that failure looked like the last time: 23 records seen, 23 errors, 0 stored).
DROP INDEX IF EXISTS public.uq_credential_findings_identity;
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



-- ===========================================================================
-- web_findings: fingerprint + dedup at the database, not in 18 call sites
-- ===========================================================================
--
-- Fingerprints only dedupe if EVERY writer computes one. They did not: of ~26
-- insert sites across 6 services, one (ZAP) computed a fingerprint. Everything
-- else wrote NULL, and NULL never conflicts, so the unique index was inert for
-- them — katana re-inserted an entire crawl every run (32,218 rows for 630
-- findings).
--
-- Patching each site is fragile (different column sets, gen_random_uuid()
-- inline, four services) and silently fails again the next time someone adds a
-- parser. Doing it here makes the invariant hold for current AND future writers.
--
-- TRADE-OFF, stated plainly: this is behaviour that is not visible at the call
-- site. An INSERT of a finding that already exists becomes an UPDATE of
-- last_seen and inserts no row. Callers relying on RETURNING id therefore get
-- no row back — only app/rag-api/api.py:4682 did, and it now handles that.
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

-- ===========================================================================
-- vulns: same dedup guard as web_findings
-- ===========================================================================
--
-- Every vulns writer currently supplies a fingerprint, so unlike web_findings
-- this is a guard against regression rather than a fix for a live leak. It has
-- two parts with VERY different confidence levels, and the difference matters:
--
--   * The DEDUP is exact. It compares the fingerprint the writer already
--     computed against what is stored; nothing is recomputed, so it cannot
--     disagree with the application.
--
--   * The FILL is BEST-EFFORT, and only runs when a writer supplies no
--     fingerprint at all. It cannot be perfectly faithful to
--     etl/fingerprint.py::vuln_fingerprint, because that hashes the ip and PORT
--     the scanner observed, while the row stores only asset_id and port_id —
--     when port_id is NULL the port is simply not recoverable. A best-effort
--     hash still deduplicates repeat inserts from the same writer, which is the
--     common case; NULL deduplicates nothing at all.
--
-- Verified against live data: reproduces 34 of 34 stored fingerprints once the
-- metadata.port fallback below is applied. (A first version got 33/34 and the
-- outlier was misread as proof of a second hash format in the data; it was in
-- fact a vuln_fingerprint row whose port lived only in metadata.)
--
-- A second format DOES exist in the code — etl/parse_tool_output.py used a local
-- _fingerprint() that is just md5 of its arguments joined by "|" — but it had not
-- written any of the live rows. That writer has since been moved onto
-- vuln_fingerprint / web_fingerprint so the two cannot diverge in future.

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

-- ===========================================================================
-- recon_findings: fingerprint + dedup
-- ===========================================================================
--
-- Every one of the 575 live rows had a NULL fingerprint: ~50 insert sites across
-- ~30 files write this table and none of them computed one. Patching them
-- individually is not realistic, so this follows the web_findings pattern and
-- enforces the invariant at the database.
--
-- THE DATA KEY IS LOAD-BEARING. recon_fingerprint takes
-- (source, finding_type, target, data_key), and `target` alone is NOT the
-- identity here: gowitness writes one row per screenshot but sets target to the
-- HOST, so all 563 of its rows share target='192.168.1.150' and differ only in
-- `data`. Keying on (source, finding_type, target) would have collapsed 575 rows
-- to 5 and destroyed 558 distinct findings. `data` must be part of the key.
--
-- Known limit: the trigger uses jsonb's canonical text form, while a Python
-- writer passing its own data_key (e.g. parse_tool_output's
-- json.dumps(rec)[:200]) may serialise differently. Rows from those two paths
-- may therefore not dedupe against each other. Supplied fingerprints are never
-- recomputed, so this only affects the fill.

UPDATE public.recon_findings
   SET fingerprint = md5('recon|' || lower(btrim(coalesce(source, '')))
                          || '|' || lower(btrim(coalesce(finding_type, '')))
                          || '|' || lower(btrim(coalesce(target, '')))
                          || '|' || lower(btrim(coalesce(data::text, ''))))
 WHERE fingerprint IS NULL;

DELETE FROM public.recon_findings a
 USING public.recon_findings b
 WHERE a.fingerprint IS NOT NULL
   AND a.fingerprint = b.fingerprint
   AND a.id <> b.id
   AND (a.created_at, a.id) < (b.created_at, b.id);

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
    -- Operator-supplied label for a manually uploaded artifact ("what is this").
    note             text,
    -- Records in THIS file (JSONL lines / JSON array length / non-blank lines),
    -- computed at ingest. The per-artifact item count — NOT a job-wide findings
    -- join, which over-counts when tools share a job_id.
    item_count       integer,
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

-- Backfill for databases created before these columns existed (idempotent).
ALTER TABLE public.raw_artifacts ADD COLUMN IF NOT EXISTS note text;
ALTER TABLE public.raw_artifacts ADD COLUMN IF NOT EXISTS item_count integer;

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

-- Existing installs: widen the evidence_links entity_type CHECK so a
-- security_test_run can be a first-class evidence entity (symmetric with
-- exploit_result). Idempotent — a fresh table already has the wider set above.
DO $$ BEGIN
  ALTER TABLE public.evidence_links DROP CONSTRAINT IF EXISTS evidence_links_entity_type_check;
  ALTER TABLE public.evidence_links ADD CONSTRAINT evidence_links_entity_type_check
    CHECK (entity_type IN ('finding','web_finding','playwright_finding','asset',
                           'checklist_item','exploit_result','security_test_run'));
EXCEPTION WHEN OTHERS THEN NULL; END $$;

GRANT ALL PRIVILEGES ON public.security_tests     TO app;
GRANT ALL PRIVILEGES ON public.security_test_runs TO app;
