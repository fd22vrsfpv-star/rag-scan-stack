#!/usr/bin/env python3
"""Create/update the detected_software view in the database."""
import os
import psycopg2

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

VIEW_SQL = """
CREATE OR REPLACE VIEW public.detected_software AS
-- Source 1: Nmap/Masscan service detection
SELECT a.id AS asset_id, host(a.ip)::text AS ip, a.hostname, p.port, p.proto AS protocol,
    COALESCE(p.product, p.service) AS product, p.version, 'nmap'::text AS source,
    'service_detection'::text AS detection_type, p.created_at AS first_seen, COALESCE(p.updated_at, p.created_at) AS last_seen
FROM public.ports p JOIN public.assets a ON p.asset_id = a.id
WHERE COALESCE(p.is_open, true) AND (p.product IS NOT NULL OR p.service IS NOT NULL)

UNION ALL
-- Source 2: httpx webserver header
SELECT a.id, host(a.ip)::text, a.hostname, NULL::integer, NULL::text,
    rf.data->>'webserver', NULL::text, 'httpx'::text, 'web_server'::text, rf.created_at, rf.created_at
FROM public.recon_findings rf LEFT JOIN public.assets a ON rf.asset_id = a.id
WHERE rf.source = 'httpx' AND rf.data->>'webserver' IS NOT NULL

UNION ALL
-- Source 3: httpx tech array
SELECT a.id, host(a.ip)::text, a.hostname, NULL::integer, NULL::text,
    tech.value::text, NULL::text, 'httpx'::text, 'tech_detection'::text, rf.created_at, rf.created_at
FROM public.recon_findings rf LEFT JOIN public.assets a ON rf.asset_id = a.id,
LATERAL jsonb_array_elements_text(rf.data->'tech') AS tech(value)
WHERE rf.source = 'httpx' AND rf.data->'tech' IS NOT NULL AND jsonb_typeof(rf.data->'tech') = 'array'

UNION ALL
-- Source 4: WhatWeb tech (splits product/version on /)
SELECT a.id, host(a.ip)::text, a.hostname, NULL::integer, NULL::text,
    CASE WHEN tech.value LIKE '%/%' THEN split_part(tech.value, '/', 1) ELSE tech.value END,
    CASE WHEN tech.value LIKE '%/%' THEN split_part(tech.value, '/', 2) ELSE NULL END,
    'whatweb'::text, 'tech_detection'::text, rf.created_at, rf.created_at
FROM public.recon_findings rf LEFT JOIN public.assets a ON rf.asset_id = a.id,
LATERAL jsonb_array_elements_text(rf.data->'tech') AS tech(value)
WHERE rf.source = 'whatweb' AND rf.data->'tech' IS NOT NULL AND jsonb_typeof(rf.data->'tech') = 'array'

UNION ALL
-- Source 5: wafw00f WAF detection
SELECT a.id, host(a.ip)::text, a.hostname, NULL::integer, NULL::text,
    rf.data->>'waf', NULL::text, 'wafw00f'::text, 'waf_detection'::text, rf.created_at, rf.created_at
FROM public.recon_findings rf LEFT JOIN public.assets a ON rf.asset_id = a.id
WHERE rf.source = 'wafw00f' AND rf.data->>'waf' IS NOT NULL

UNION ALL
-- Source 6: ZAP "Tech Detected - X" alerts
SELECT wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')), a.hostname,
    NULL::integer, NULL::text,
    CASE WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 1)
         ELSE substring(wf.name from 'Tech Detected - (.+)') END,
    CASE WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 2) ELSE NULL END,
    'zap'::text, 'tech_detection'::text, wf.first_seen, wf.last_seen
FROM public.web_findings wf LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'zap' AND wf.name LIKE 'Tech Detected%'

UNION ALL
-- Source 7: ZAP Server header / X-Powered-By leaks
SELECT wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')), a.hostname,
    NULL::integer, NULL::text,
    CASE WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 1) ELSE wf.evidence END,
    CASE WHEN wf.evidence LIKE '%/%' THEN split_part(wf.evidence, '/', 2) ELSE NULL END,
    'zap'::text,
    CASE WHEN wf.name ILIKE '%server%' THEN 'server_header'
         WHEN wf.name ILIKE '%powered%' THEN 'x_powered_by'
         ELSE 'version_leak' END::text,
    wf.first_seen, wf.last_seen
FROM public.web_findings wf LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'zap' AND wf.evidence IS NOT NULL AND wf.evidence != ''
  AND (wf.name ILIKE '%server leak%' OR wf.name ILIKE '%x-powered%' OR wf.name ILIKE '%version info%')

UNION ALL
-- Source 8: Nuclei tech-detect templates
SELECT wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')), a.hostname,
    NULL::integer, NULL::text,
    wf.name, NULL::text, 'nuclei'::text, 'tech_detection'::text,
    wf.first_seen, wf.last_seen
FROM public.web_findings wf LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'nuclei' AND (wf.issue_type ILIKE '%tech%' OR wf.issue_type ILIKE '%detect%' OR wf.name ILIKE '%detect%')

UNION ALL
-- Source 9: Katana JS/CSS with ?ver= query param (e.g. jquery.min.js?ver=3.7.1)
SELECT DISTINCT ON (substring(wf.url from '://([^/:]+)'),
    regexp_replace(substring(wf.url from '/([^/?]+)\.(min\.)?[jc]ss?(\?|$)'), '[-.](\d+[\d.]*\d)$', '', 'g'),
    substring(wf.url from '[?&]ver?=([0-9][0-9.]+)'))
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')), a.hostname,
    NULL::integer, NULL::text,
    regexp_replace(
        substring(wf.url from '/([^/?]+)\.(min\.)?[jc]ss?(\?|$)'),
        '[-.](\d+[\d.]*\d)$', '', 'g'
    ),
    substring(wf.url from '[?&]ver?=([0-9][0-9.]+)'),
    'katana'::text, 'js_library'::text,
    wf.first_seen, wf.last_seen
FROM public.web_findings wf LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'katana' AND wf.url ~ '\.(js|css)(\?|$)' AND wf.url ~ '[?&]ver?=[0-9]'

UNION ALL
-- Source 10: Katana JS/CSS with version in filename (e.g. foundation.6.2.3_custom.js)
SELECT DISTINCT ON (substring(wf.url from '://([^/:]+)'),
    regexp_replace(substring(wf.url from '/([^/]+)\.(min\.)?[jc]ss?(\?|$)'), '[-._](\d+\.)+\d+.*$', ''),
    substring(wf.url from '/[^/]*?[-._](\d+\.\d+[\d.]*)\.(min\.)?[jc]ss?'))
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')), a.hostname,
    NULL::integer, NULL::text,
    regexp_replace(
        substring(wf.url from '/([^/]+)\.(min\.)?[jc]ss?(\?|$)'),
        '[-._](\d+\.)+\d+.*$', ''
    ),
    substring(wf.url from '/[^/]*?[-._](\d+\.\d+[\d.]*)\.(min\.)?[jc]ss?'),
    'katana'::text, 'js_library'::text,
    wf.first_seen, wf.last_seen
FROM public.web_findings wf LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.source = 'katana' AND wf.url ~ '\.(js|css)(\?|$)'
  AND wf.url ~ '/[^/]*[-._]\d+\.\d+[^/]*\.(min\.)?[jc]ss?'
  AND NOT wf.url ~ '[?&]ver?=[0-9]'

UNION ALL
-- Source 11: Copyright year detection from HTML responses (katana/httpx/whatweb evidence)
SELECT DISTINCT ON (substring(wf.url from '://([^/:]+)'), wf.name)
    wf.asset_id,
    COALESCE(host(a.ip)::text, substring(wf.url from '://([^/:]+)')), a.hostname,
    NULL::integer, NULL::text,
    wf.name AS product,
    substring(wf.evidence from '(?:©|\(c\)|copyright)\s*(\d{4})') AS version,
    wf.source::text,
    'copyright_year'::text AS detection_type,
    wf.first_seen, wf.last_seen
FROM public.web_findings wf LEFT JOIN public.assets a ON wf.asset_id = a.id
WHERE wf.evidence ~ '(?i)(©|\(c\)|copyright)\s*\d{4}'
  AND wf.source IN ('katana', 'httpx', 'whatweb', 'nikto', 'zap')
"""


def main():
    conn = psycopg2.connect(DB_DSN)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("DROP VIEW IF EXISTS detected_software")
    cur.execute(VIEW_SQL)
    print("View created with all sources")

    cur.execute("SELECT source, detection_type, COUNT(*) FROM detected_software GROUP BY source, detection_type ORDER BY source, count DESC")
    print("\n--- Detection counts ---")
    for r in cur.fetchall():
        print(f"  {r[0]:10s}  {r[1]:20s}  {r[2]:5d}")

    cur.execute("SELECT COUNT(DISTINCT ip), COUNT(DISTINCT product), COUNT(*) FROM detected_software")
    r = cur.fetchone()
    print(f"\nTotal: {r[2]} detections, {r[1]} products, {r[0]} assets")

    cur.execute("SELECT product, version, source, detection_type FROM detected_software WHERE source = 'katana' LIMIT 20")
    rows = cur.fetchall()
    if rows:
        print("\n--- Katana JS library samples ---")
        for r in rows:
            print(f"  {r[0] or '(none)':40s}  v{r[1] or '?':10s}  ({r[2]}) {r[3]}")

    cur.execute("SELECT product, version, source, detection_type FROM detected_software WHERE detection_type = 'copyright_year' LIMIT 20")
    rows = cur.fetchall()
    if rows:
        print("\n--- Copyright year samples ---")
        for r in rows:
            print(f"  {r[0] or '(none)':40s}  (c) {r[1] or '?':6s}  ({r[2]})")

    conn.close()


if __name__ == "__main__":
    main()
