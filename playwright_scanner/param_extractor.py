"""
Parameter Extractor - Discovers and saves URL/form/body parameters from Playwright network logs.
Saves to discovered_params table for use in wordlist generation and attack surface mapping.
"""

import re
import logging
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional
import json

from db_utils import get_db
from psycopg2.extras import RealDictCursor

# The ONE answer to "which engagement does this host belong to?" (asset first,
# then its scope entry, None when it cannot be tied to one). Shared with the
# katana parser rather than re-derived -- a second resolver is how the question
# comes to mean two different things. ./etl is bind-mounted into this image.
try:
    from etl.identity_upsert import resolve_engagement_for_host
except Exception:  # pragma: no cover - deployment problem, not a code path
    resolve_engagement_for_host = None

logger = logging.getLogger("param-extractor")

# A row whose engagement cannot be resolved stays NULL here and is folded into
# the nil-UUID bucket by uq_discovered_params_identity's COALESCE -- a NULL in
# an indexed column makes two rows non-equal in Postgres, so leaving it NULL in
# the KEY would switch dedup off for that row entirely.
def _engagement_for_asset(cur, asset_id):
    """The engagement column off the asset row these params already link to.

    Not a second resolver -- it is step 1 of resolve_engagement_for_host keyed by
    the asset id we already hold, for the url_patterns that carry no host at all
    ('(inline-form)', a relative form action). Without it those rows land in the
    shared nil-engagement bucket and two engagements collide there exactly the
    way they used to collide everywhere.
    """
    if not asset_id:
        return None
    # Its own savepoint: a failed SELECT leaves the transaction ABORTED in
    # Postgres, which would take every param insert below down with it.
    try:
        cur.execute("SAVEPOINT pe_eng_asset")
        cur.execute("SELECT engagement_id FROM assets WHERE id = %s", (str(asset_id),))
        row = cur.fetchone()
        cur.execute("RELEASE SAVEPOINT pe_eng_asset")
    except Exception:
        try:
            cur.execute("ROLLBACK TO SAVEPOINT pe_eng_asset")
        except Exception:
            pass
        return None
    if row is None:
        return None
    return row.get("engagement_id") if isinstance(row, dict) else row[0]


def _engagement_for_url(cur, url_pattern, cache, fallback=None):
    """engagement_id for a captured URL's host, memoised per host for the run."""
    if resolve_engagement_for_host is None:
        return fallback
    try:
        host = (urlparse(url_pattern or "").hostname or "").strip()
    except Exception:
        host = ""
    if not host:
        return fallback
    if host not in cache:
        # Same reason as _engagement_for_asset: the shared helper swallows its
        # exception but the transaction stays aborted without a savepoint.
        try:
            cur.execute("SAVEPOINT pe_eng_host")
            cache[host] = resolve_engagement_for_host(cur, host)
            cur.execute("RELEASE SAVEPOINT pe_eng_host")
        except Exception:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT pe_eng_host")
            except Exception:
                pass
            cache[host] = None
    return cache[host] or fallback


def _infer_type(value: str) -> str:
    """Infer parameter type from sample value."""
    if not value:
        return 'string'
    v = value.strip()
    if v.lower() in ('true', 'false', '0', '1', 'yes', 'no'):
        return 'boolean'
    if re.match(r'^-?\d+$', v):
        return 'integer'
    if re.match(r'^-?\d+\.\d+$', v):
        return 'float'
    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.I):
        return 'uuid'
    if re.match(r'^[^@]+@[^@]+\.[^@]+$', v):
        return 'email'
    if v.startswith('/') and '/' in v[1:]:
        return 'path'
    if len(v) > 16 and re.match(r'^[A-Za-z0-9+/=]+$', v):
        return 'encoded'
    return 'string'


def extract_params_from_network(
    network_logs: List[Dict],
    forms: List[Dict],
    asset_id,
    discovery_source: str = 'playwright',
) -> Dict:
    """
    Extract parameters from captured network requests and DOM forms.

    Args:
        network_logs: List of {url, method, type, post_data?, headers?}
        forms: List of form dicts from DOM analysis
        asset_id: Asset UUID
        discovery_source: Source label for discovered_params

    Returns:
        Stats dict with counts
    """
    params_seen = {}  # (url_pattern, name, method, location) -> {type, values}

    # 1. Extract from network request URLs (query params)
    for log in network_logs:
        url = log.get('url', '')
        method = log.get('method', 'GET').upper()
        rtype = log.get('type', '')

        # Skip static assets
        if rtype in ('stylesheet', 'image', 'font', 'media'):
            continue

        parsed = urlparse(url)
        if not parsed.query:
            continue

        url_pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for name, vals in qs.items():
            sample = vals[0] if vals else ''
            key = (url_pattern, name, method, 'query')
            if key not in params_seen:
                params_seen[key] = {'type': _infer_type(sample), 'values': set()}
            params_seen[key]['values'].add(sample[:200])

    # 2. Extract from POST bodies
    for log in network_logs:
        method = log.get('method', 'GET').upper()
        if method not in ('POST', 'PUT', 'PATCH'):
            continue

        post_data = log.get('post_data', '')
        if not post_data:
            continue

        url = log.get('url', '')
        parsed = urlparse(url)
        url_pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Try JSON body
        if post_data.strip().startswith('{'):
            try:
                body = json.loads(post_data)
                if isinstance(body, dict):
                    for name, val in body.items():
                        sample = str(val)[:200] if val is not None else ''
                        key = (url_pattern, name, method, 'json_body')
                        if key not in params_seen:
                            params_seen[key] = {'type': _infer_type(sample), 'values': set()}
                        params_seen[key]['values'].add(sample)
            except json.JSONDecodeError:
                pass
        else:
            # Try form-encoded body
            try:
                body_params = parse_qs(post_data.strip(), keep_blank_values=True)
                for name, vals in body_params.items():
                    sample = vals[0] if vals else ''
                    key = (url_pattern, name, method, 'body')
                    if key not in params_seen:
                        params_seen[key] = {'type': _infer_type(sample), 'values': set()}
                    params_seen[key]['values'].add(sample[:200])
            except Exception:
                pass

    # 3. Extract from DOM forms (even unsubmitted)
    for form in (forms or []):
        action = form.get('action', '')
        method = (form.get('method', 'GET') or 'GET').upper()
        if action:
            parsed = urlparse(action)
            url_pattern = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else action
        else:
            url_pattern = '(inline-form)'

        for inp in form.get('inputs', []):
            name = inp.get('name', '')
            if not name:
                continue
            inp_type = inp.get('type', 'text')
            value = inp.get('value', '')
            location = 'body' if method == 'POST' else 'query'
            key = (url_pattern, name, method, location)
            if key not in params_seen:
                param_type = 'password' if inp_type == 'password' else _infer_type(value)
                params_seen[key] = {'type': param_type, 'values': set()}
            if value and inp_type != 'password':
                params_seen[key]['values'].add(value[:200])

    # 4. Save to database
    saved = 0
    if params_seen:
        # host -> engagement_id, resolved once per host for this extraction.
        eng_cache = {}
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            asset_engagement = _engagement_for_asset(cur, asset_id)
            for (url_pattern, name, method, location), info in params_seen.items():
                try:
                    sample_arr = list(info['values'])[:5] if info['values'] else None
                    # Collected target data MUST carry the engagement (CLAUDE.md
                    # "Engagement attribution is mandatory"), and here it is also
                    # half the dedup key: url_pattern carries only
                    # scheme://netloc/path, so without it a second engagement
                    # scanning the same address UPDATEd the first engagement's
                    # row instead of inserting its own.
                    engagement_id = _engagement_for_url(
                        cur, url_pattern, eng_cache, fallback=asset_engagement)
                    # The ON CONFLICT expression must stay character-identical to
                    # uq_discovered_params_identity in
                    # db_init/ensure_all_tables.sql -- a mismatch is not a silent
                    # fallback, it raises "no unique or exclusion constraint
                    # matching the ON CONFLICT specification" on every row.
                    cur.execute("""
                        INSERT INTO discovered_params
                            (asset_id, engagement_id, url_pattern, param_name, param_type,
                             http_method, param_location, sample_values,
                             occurrence_count, discovery_source)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s)
                        ON CONFLICT (COALESCE(engagement_id, '00000000-0000-0000-0000-000000000000'::uuid),
                                     url_pattern,
                                     param_name,
                                     COALESCE(http_method, 'GET'),
                                     COALESCE(param_location, 'query'))
                        DO UPDATE SET
                            occurrence_count = discovered_params.occurrence_count + 1,
                            last_seen = now(),
                            discovery_source = CASE
                                WHEN discovered_params.discovery_source NOT LIKE '%%' || %s || '%%'
                                THEN discovered_params.discovery_source || ',' || %s
                                ELSE discovered_params.discovery_source
                            END
                    """, (
                        str(asset_id) if asset_id else None,
                        str(engagement_id) if engagement_id else None,
                        url_pattern[:500], name[:200], info['type'],
                        method, location, sample_arr,
                        discovery_source,
                        discovery_source, discovery_source,
                    ))
                    saved += 1
                except Exception as e:
                    logger.warning("Param upsert failed for %s.%s: %s", url_pattern, name, e)
            conn.commit()

    logger.info("Extracted %d unique params (%d saved to DB)", len(params_seen), saved)
    return {
        'total_params': len(params_seen),
        'saved': saved,
        'query_params': sum(1 for k in params_seen if k[3] == 'query'),
        'body_params': sum(1 for k in params_seen if k[3] in ('body', 'json_body')),
        'form_params': sum(1 for k in params_seen if k[0] == '(inline-form)' or k[3] == 'body'),
    }
