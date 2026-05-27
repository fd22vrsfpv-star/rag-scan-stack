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

logger = logging.getLogger("param-extractor")


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
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            for (url_pattern, name, method, location), info in params_seen.items():
                try:
                    sample_arr = list(info['values'])[:5] if info['values'] else None
                    cur.execute("""
                        INSERT INTO discovered_params
                            (asset_id, url_pattern, param_name, param_type,
                             http_method, param_location, sample_values,
                             occurrence_count, discovery_source)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, 1, %s)
                        ON CONFLICT (url_pattern, param_name, http_method, param_location)
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
