"""
Wordlist Generator - CeWL-style wordlist generation from content extractions.
Pure Python, no Playwright dependency. Queries content_extractions from DB
and generates targeted wordlists for credential testing.
"""

import os
import re
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from db_utils import get_db, get_content_extractions
from psycopg2.extras import RealDictCursor, Json

logger = logging.getLogger("wordlist-generator")

WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/wordlists")

# Common stopwords to filter
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

# HTML/JS keywords to filter
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

# L33t speak substitutions
LEET_MAP = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1'}

WORD_RE = re.compile(r'[a-zA-Z]{2,}')


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
    """
    Generate a wordlist from content extractions.

    Args:
        asset_id: Filter extractions by asset
        scan_id: Filter extractions by scan
        list_type: 'passwords', 'usernames', or 'directories'
        min_word_length: Minimum word length (default 5)
        max_lines: Maximum output lines (default 50000)
        enable_mutations: Apply password mutations
        mutations: Which mutations to apply. Options:
            capitalize, upper, leet, append_numbers, append_specials, append_years
        include_sources: Which extraction fields to use. Options:
            word_corpus, emails, names, tech_indicators, comments, hidden_inputs, params

    Returns:
        Dict with wordlist_id, name, line_count, path
    """
    if mutations is None:
        mutations = ['capitalize', 'upper', 'leet', 'append_numbers', 'append_specials', 'append_years']
    if include_sources is None:
        include_sources = ['word_corpus', 'emails', 'names', 'tech_indicators', 'comments', 'hidden_inputs']

    # Fetch extractions
    extractions = get_content_extractions(
        asset_id=asset_id,
        scan_id=scan_id,
        limit=500,
    )

    if not extractions:
        raise ValueError("No content extractions found for the given filters")

    # Determine hostname for file naming
    hostname = 'unknown'
    if extractions:
        try:
            parsed = urlparse(extractions[0].get('url', ''))
            hostname = parsed.netloc or 'unknown'
        except Exception:
            pass
    hostname_safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', hostname)

    # Collect raw tokens based on list type
    if list_type == 'usernames':
        words = _collect_username_tokens(extractions, include_sources)
    elif list_type == 'directories':
        words = _collect_directory_tokens(extractions, include_sources)
    else:
        words = _collect_password_tokens(extractions, include_sources, min_word_length)

    # Apply mutations for passwords
    if list_type == 'passwords' and enable_mutations:
        words = _apply_mutations(words, mutations, max_lines)

    # Deduplicate and cap
    unique_words = list(dict.fromkeys(words))[:max_lines]

    # Write to file
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    filename = f"cewl_{hostname_safe}_{list_type}_{timestamp}.txt"
    filepath = os.path.join(WORDLIST_DIR, filename)

    with open(filepath, 'w') as f:
        for word in unique_words:
            f.write(word + '\n')

    line_count = len(unique_words)
    size_bytes = os.path.getsize(filepath)

    # Register in wordlists table
    wordlist_id = _register_wordlist(filename, filepath, list_type, line_count, size_bytes, hostname_safe)

    logger.info("Generated %s wordlist: %s (%d lines, %d bytes)", list_type, filename, line_count, size_bytes)

    return {
        'wordlist_id': str(wordlist_id),
        'name': filename,
        'line_count': line_count,
        'size_bytes': size_bytes,
        'path': filepath,
    }


def _collect_password_tokens(
    extractions: List[Dict],
    include_sources: List[str],
    min_length: int,
) -> List[str]:
    """Collect words for password wordlists."""
    words: List[str] = []

    for ext in extractions:
        # Word corpus
        if 'word_corpus' in include_sources:
            corpus = ext.get('word_corpus', '') or ''
            for m in WORD_RE.finditer(corpus):
                word = m.group()
                if len(word) >= min_length and word.lower() not in STOPWORDS and word.lower() not in CODE_KEYWORDS:
                    words.append(word)

        # Email local parts
        if 'emails' in include_sources:
            for email in (ext.get('emails') or []):
                local = email.split('@')[0]
                if len(local) >= min_length:
                    words.append(local)

        # Names
        if 'names' in include_sources:
            for name in (ext.get('names') or []):
                parts = name.split()
                for part in parts:
                    if len(part) >= min_length:
                        words.append(part)
                if len(parts) >= 2:
                    words.append(''.join(parts))  # concatenated

        # Tech indicators
        if 'tech_indicators' in include_sources:
            for tech in (ext.get('tech_indicators') or []):
                val = tech.get('value', '')
                for m in WORD_RE.finditer(val):
                    word = m.group()
                    if len(word) >= min_length:
                        words.append(word)

        # Comments
        if 'comments' in include_sources:
            for comment in (ext.get('comments') or []):
                content = comment.get('content', '')
                for m in WORD_RE.finditer(content):
                    word = m.group()
                    if len(word) >= min_length and word.lower() not in STOPWORDS:
                        words.append(word)

        # Hidden inputs (param names and values)
        if 'hidden_inputs' in include_sources:
            for inp in (ext.get('hidden_inputs') or []):
                name = inp.get('name', '')
                value = inp.get('value', '')
                if len(name) >= min_length:
                    words.append(name)
                if value and len(value) >= min_length and not value.startswith(('http', '/')):
                    words.append(value)

    return words


def _collect_username_tokens(extractions: List[Dict], include_sources: List[str]) -> List[str]:
    """Collect tokens for username wordlists."""
    usernames: List[str] = []

    for ext in extractions:
        # Email local parts
        if 'emails' in include_sources:
            for email in (ext.get('emails') or []):
                local = email.split('@')[0]
                usernames.append(local)

        # Names -> username patterns
        if 'names' in include_sources:
            for name in (ext.get('names') or []):
                parts = name.split()
                if len(parts) >= 2:
                    first = parts[0].lower()
                    last = parts[-1].lower()
                    # Common username patterns
                    usernames.extend([
                        first,
                        last,
                        f"{first}.{last}",
                        f"{first}{last}",
                        f"{first[0]}{last}",          # flast
                        f"{first}{last[0]}",           # firstl
                        f"{first[0]}.{last}",          # f.last
                        f"{first}_{last}",
                    ])
                elif len(parts) == 1:
                    usernames.append(parts[0].lower())

    return usernames


def _collect_directory_tokens(extractions: List[Dict], include_sources: List[str]) -> List[str]:
    """Collect tokens for directory/path wordlists."""
    dirs: List[str] = []

    for ext in extractions:
        # Internal paths
        for path in (ext.get('internal_paths') or []):
            dirs.append(path)
            # Also add individual path segments
            for segment in path.strip('/').split('/'):
                if segment and len(segment) >= 2:
                    dirs.append(segment)

        # API endpoints
        for endpoint in (ext.get('api_endpoints') or []):
            dirs.append(endpoint)
            for segment in endpoint.strip('/').split('/'):
                if segment and len(segment) >= 2:
                    dirs.append(segment)

        # Hidden input names as potential param names
        if 'hidden_inputs' in include_sources:
            for inp in (ext.get('hidden_inputs') or []):
                name = inp.get('name', '')
                if name:
                    dirs.append(name)

    return dirs


def _apply_mutations(words: List[str], mutations: List[str], max_lines: int) -> List[str]:
    """Apply password mutations to word list."""
    result: List[str] = list(words)  # originals first

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
        suffixes = ['1', '12', '123', '1234', '0', '00', '01', '99']
        for w in words:
            for s in suffixes:
                result.append(w + s)

    if 'append_specials' in mutations:
        specials = ['!', '@', '#', '$', '!1', '@1', '#1']
        for w in words:
            for s in specials:
                result.append(w + s)

    if 'append_years' in mutations:
        current_year = datetime.utcnow().year
        years = [str(y) for y in range(current_year - 3, current_year + 2)]
        for w in words:
            for y in years:
                result.append(w + y)

    return result[:max_lines]


def _register_wordlist(
    name: str,
    path: str,
    list_type: str,
    line_count: int,
    size_bytes: int,
    hostname: str,
) -> uuid.UUID:
    """Register generated wordlist in the wordlists table."""
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO wordlists (name, path, source, list_type, line_count, size_bytes, description)
            VALUES (%s, %s, 'cewl-generated', %s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE SET
              path = EXCLUDED.path, line_count = EXCLUDED.line_count,
              size_bytes = EXCLUDED.size_bytes, description = EXCLUDED.description
            RETURNING id
            """,
            (name, path, list_type, line_count, size_bytes,
             f"CeWL-generated {list_type} wordlist from {hostname}"),
        )
        wl_id = cur.fetchone()['id']
        conn.commit()
        return wl_id
