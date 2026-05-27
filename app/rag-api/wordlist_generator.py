"""
Wordlist Generator - CeWL-style wordlist generation from content extractions.
Pure Python. Queries content_extractions from DB and generates targeted wordlists
for credential testing.
"""

import os
import re
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("wordlist-generator")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/wordlists")

STOPWORDS = frozenset({
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
    'her', 'was', 'one', 'our', 'out', 'has', 'have', 'been', 'some', 'them',
    'than', 'its', 'over', 'also', 'that', 'this', 'with', 'will', 'each',
    'from', 'they', 'were', 'which', 'their', 'said', 'what', 'when', 'where',
    'into', 'more', 'other', 'about', 'such', 'there', 'these', 'those',
    'then', 'just', 'your', 'here', 'could', 'would', 'should', 'very',
    'been', 'being', 'because', 'between', 'before', 'after', 'above',
    'below', 'under', 'again', 'once', 'while', 'during', 'until',
    'through', 'both', 'does', 'doing', 'only', 'same', 'most',
    'nbsp', 'null', 'undefined', 'true', 'false', 'none', 'class',
})

CODE_KEYWORDS = frozenset({
    'function', 'return', 'const', 'class', 'export', 'import', 'default',
    'static', 'async', 'await', 'yield', 'throw', 'catch', 'finally',
    'typeof', 'instanceof', 'delete', 'switch', 'break', 'continue',
    'while', 'document', 'window', 'console', 'prototype', 'constructor',
    'margin', 'padding', 'border', 'display', 'position', 'color',
    'width', 'height', 'background', 'content', 'style', 'xmlns',
    'script', 'onclick', 'onload', 'href', 'string', 'number',
    'boolean', 'object', 'array', 'props', 'state', 'render',
    'component', 'module', 'require', 'exports', 'define',
})

LEET_MAP = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1'}
WORD_RE = re.compile(r'[a-zA-Z]{2,}')


def _get_db():
    return psycopg2.connect(DB_DSN)


def _fetch_extractions(asset_id=None, scan_id=None, limit=500):
    """Fetch content extractions from DB."""
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            conditions = []
            params = []
            if asset_id:
                conditions.append("asset_id = %s")
                params.append(asset_id)
            if scan_id:
                conditions.append("scan_id = %s")
                params.append(scan_id)
            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            params.append(limit)
            cur.execute(
                f"SELECT * FROM content_extractions {where} ORDER BY created_at DESC LIMIT %s",
                params,
            )
            return cur.fetchall()
    finally:
        conn.close()


def generate_wordlist(
    asset_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    list_type: str = 'passwords',
    min_word_length: int = 5,
    max_lines: int = 50000,
    enable_mutations: bool = True,
    mutations: Optional[List[str]] = None,
    include_sources: Optional[List[str]] = None,
) -> Dict:
    if mutations is None:
        mutations = ['capitalize', 'upper', 'leet', 'append_numbers', 'append_specials', 'append_years']
    if include_sources is None:
        include_sources = ['word_corpus', 'emails', 'names', 'tech_indicators', 'comments', 'hidden_inputs']

    extractions = _fetch_extractions(asset_id=asset_id, scan_id=scan_id)
    if not extractions:
        raise ValueError("No content extractions found for the given filters")

    hostname = 'unknown'
    try:
        parsed = urlparse(extractions[0].get('url', ''))
        hostname = parsed.netloc or 'unknown'
    except Exception:
        pass
    hostname_safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', hostname)

    if list_type == 'usernames':
        words = _collect_username_tokens(extractions, include_sources)
    elif list_type == 'directories':
        words = _collect_directory_tokens(extractions, include_sources)
    else:
        words = _collect_password_tokens(extractions, include_sources, min_word_length)

    if list_type == 'passwords' and enable_mutations:
        words = _apply_mutations(words, mutations, max_lines)

    unique_words = list(dict.fromkeys(words))[:max_lines]

    os.makedirs(WORDLIST_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"cewl_{hostname_safe}_{list_type}_{timestamp}.txt"
    filepath = os.path.join(WORDLIST_DIR, filename)

    with open(filepath, 'w') as f:
        for word in unique_words:
            f.write(word + '\n')

    line_count = len(unique_words)
    size_bytes = os.path.getsize(filepath)

    wordlist_id = _register_wordlist(filename, filepath, list_type, line_count, size_bytes, hostname_safe)
    logger.info("Generated %s wordlist: %s (%d lines, %d bytes)", list_type, filename, line_count, size_bytes)

    return {
        'wordlist_id': str(wordlist_id),
        'name': filename,
        'line_count': line_count,
        'size_bytes': size_bytes,
        'path': filepath,
    }


def _collect_password_tokens(extractions, include_sources, min_length):
    words = []
    for ext in extractions:
        if 'word_corpus' in include_sources:
            corpus = ext.get('word_corpus', '') or ''
            for m in WORD_RE.finditer(corpus):
                word = m.group()
                if len(word) >= min_length and word.lower() not in STOPWORDS and word.lower() not in CODE_KEYWORDS:
                    words.append(word)
        if 'emails' in include_sources:
            for email in (ext.get('emails') or []):
                local = email.split('@')[0]
                if len(local) >= min_length:
                    words.append(local)
        if 'names' in include_sources:
            for name in (ext.get('names') or []):
                parts = name.split()
                for part in parts:
                    if len(part) >= min_length:
                        words.append(part)
                if len(parts) >= 2:
                    words.append(''.join(parts))
        if 'tech_indicators' in include_sources:
            for tech in (ext.get('tech_indicators') or []):
                val = tech.get('value', '')
                for m in WORD_RE.finditer(val):
                    word = m.group()
                    if len(word) >= min_length:
                        words.append(word)
        if 'comments' in include_sources:
            for comment in (ext.get('comments') or []):
                content = comment.get('content', '')
                for m in WORD_RE.finditer(content):
                    word = m.group()
                    if len(word) >= min_length and word.lower() not in STOPWORDS:
                        words.append(word)
        if 'hidden_inputs' in include_sources:
            for inp in (ext.get('hidden_inputs') or []):
                name = inp.get('name', '')
                value = inp.get('value', '')
                if len(name) >= min_length:
                    words.append(name)
                if value and len(value) >= min_length and not value.startswith(('http', '/')):
                    words.append(value)
    return words


def _collect_username_tokens(extractions, include_sources):
    usernames = []
    for ext in extractions:
        if 'emails' in include_sources:
            for email in (ext.get('emails') or []):
                local = email.split('@')[0]
                usernames.append(local)
        if 'names' in include_sources:
            for name in (ext.get('names') or []):
                parts = name.split()
                if len(parts) >= 2:
                    first = parts[0].lower()
                    last = parts[-1].lower()
                    usernames.extend([
                        first, last,
                        f"{first}.{last}", f"{first}{last}",
                        f"{first[0]}{last}", f"{first}{last[0]}",
                        f"{first[0]}.{last}", f"{first}_{last}",
                    ])
                elif len(parts) == 1:
                    usernames.append(parts[0].lower())
    return usernames


def _collect_directory_tokens(extractions, include_sources):
    dirs = []
    for ext in extractions:
        for path in (ext.get('internal_paths') or []):
            dirs.append(path)
            for segment in path.strip('/').split('/'):
                if segment and len(segment) >= 2:
                    dirs.append(segment)
        for endpoint in (ext.get('api_endpoints') or []):
            dirs.append(endpoint)
            for segment in endpoint.strip('/').split('/'):
                if segment and len(segment) >= 2:
                    dirs.append(segment)
        if 'hidden_inputs' in include_sources:
            for inp in (ext.get('hidden_inputs') or []):
                name = inp.get('name', '')
                if name:
                    dirs.append(name)
    return dirs


def _apply_mutations(words, mutations, max_lines):
    result = list(words)
    if 'capitalize' in mutations:
        result.extend(w.capitalize() for w in words)
    if 'upper' in mutations:
        result.extend(w.upper() for w in words)
    if 'leet' in mutations:
        for w in words:
            leet = w.lower()
            for char, replacement in LEET_MAP.items():
                leet = leet.replace(char, replacement)
            if leet != w.lower():
                result.append(leet)
    if 'append_numbers' in mutations:
        for w in words:
            for s in ['1', '12', '123', '1234', '0', '00', '01', '99']:
                result.append(w + s)
    if 'append_specials' in mutations:
        for w in words:
            for s in ['!', '@', '#', '$', '!1', '@1', '#1']:
                result.append(w + s)
    if 'append_years' in mutations:
        current_year = datetime.utcnow().year
        for w in words:
            for y in [str(yr) for yr in range(current_year - 3, current_year + 2)]:
                result.append(w + y)
    return result[:max_lines]


def _register_wordlist(name, path, list_type, line_count, size_bytes, hostname):
    conn = _get_db()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """INSERT INTO wordlists (name, path, source, list_type, line_count, size_bytes, description)
                   VALUES (%s, %s, 'cewl-generated', %s, %s, %s, %s)
                   ON CONFLICT (name) DO UPDATE SET
                     path = EXCLUDED.path, line_count = EXCLUDED.line_count,
                     size_bytes = EXCLUDED.size_bytes, description = EXCLUDED.description
                   RETURNING id""",
                (name, path, list_type, line_count, size_bytes,
                 f"CeWL-generated {list_type} wordlist from {hostname}"),
            )
            wl_id = cur.fetchone()['id']
            conn.commit()
            return wl_id
    finally:
        conn.close()
