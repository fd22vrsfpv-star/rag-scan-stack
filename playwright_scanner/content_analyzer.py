"""
Content Analyzer - Extracts intelligence from spidered page DOM snapshots.
Runs after DOM analysis to collect emails, names, internal paths, API endpoints,
exposed keys, tech indicators, comments, hidden inputs, JS configs, and word corpus.
"""

import re
import json
import logging
from html.parser import HTMLParser
from typing import Dict, List, Optional, Any

logger = logging.getLogger("content-analyzer")

# ---------- regex patterns ----------

EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
)
# False-positive filters: image retina suffixes, CSS selectors, common non-emails
EMAIL_FALSE_POSITIVES = re.compile(
    r'@2x\.|@3x\.|@media|@keyframes|@import|@charset|@font-face|@supports|@page|@namespace',
    re.IGNORECASE,
)

INTERNAL_PATH_RE = re.compile(
    r'(?:href|src|action|data-[\w-]+)\s*=\s*["\'](/[a-zA-Z0-9_./-]+)["\']',
)

API_ENDPOINT_RE = re.compile(
    r'["\'](/(?:api|v[0-9]+|graphql|rest|ws)[/a-zA-Z0-9_.?&=-]*)["\']',
    re.IGNORECASE,
)

JS_STRING_PATH_RE = re.compile(
    r'["\'](/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_.-]+)+)["\']',
)

# Secret / key patterns in JS
SECRET_PATTERNS = [
    (re.compile(r'(?:api[_-]?key|apiKey)\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE), 'api_key'),
    (re.compile(r'(?:Bearer\s+)([A-Za-z0-9\-._~+/]+=*)', re.IGNORECASE), 'bearer_token'),
    (re.compile(r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE), 'password'),
    (re.compile(r'(?:secret|token|auth)[_-]?\w*\s*[:=]\s*["\']([^"\']{8,})["\']', re.IGNORECASE), 'secret'),
    (re.compile(r'(?:aws_access_key_id)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', re.IGNORECASE), 'aws_key'),
    (re.compile(r'(?:AKIA[0-9A-Z]{16})', re.IGNORECASE), 'aws_access_key'),
]

# Comment patterns with sensitive content
SENSITIVE_COMMENT_RE = re.compile(
    r'(?:password|passwd|pwd|TODO|FIXME|HACK|BUG|XXX|debug|admin|secret|credential|token|key)',
    re.IGNORECASE,
)

# Technology indicators
TECH_PATTERNS = [
    (re.compile(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE), 'generator'),
    (re.compile(r'wp-content|wp-includes|wordpress', re.IGNORECASE), 'wordpress'),
    (re.compile(r'Drupal|drupal\.js|drupal\.settings', re.IGNORECASE), 'drupal'),
    (re.compile(r'Joomla|com_content|/media/jui/', re.IGNORECASE), 'joomla'),
    (re.compile(r'X-Powered-By:\s*([^\r\n]+)', re.IGNORECASE), 'x-powered-by'),
    (re.compile(r'<meta\s+name=["\']application-name["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE), 'application'),
    (re.compile(r'react|__NEXT_DATA__|next\.js|nuxt|vue\.js|angular', re.IGNORECASE), 'js_framework'),
    # Atlassian products
    (re.compile(r'atlassian|confluence|jira|bitbucket|bamboo|crowd|fisheye', re.IGNORECASE), 'atlassian'),
    # Common web servers/platforms
    (re.compile(r'SharePoint|/_layouts/|/_vti_bin/', re.IGNORECASE), 'sharepoint'),
    (re.compile(r'phpMyAdmin|phpmyadmin', re.IGNORECASE), 'phpmyadmin'),
    (re.compile(r'GitLab|gitlab', re.IGNORECASE), 'gitlab'),
    (re.compile(r'Jenkins|/jenkins/', re.IGNORECASE), 'jenkins'),
    (re.compile(r'Grafana|grafana', re.IGNORECASE), 'grafana'),
    (re.compile(r'SonarQube|sonarqube', re.IGNORECASE), 'sonarqube'),
    (re.compile(r'Kibana|kibana|elastic', re.IGNORECASE), 'elastic'),
    (re.compile(r'Apache Tomcat|tomcat', re.IGNORECASE), 'tomcat'),
    (re.compile(r'IIS|Microsoft-IIS', re.IGNORECASE), 'iis'),
    (re.compile(r'nginx', re.IGNORECASE), 'nginx'),
]

# JS config objects
# Login page indicators
LOGIN_FORM_RE = re.compile(
    r'<form[^>]*>(?:(?!</form>).)*?<input[^>]*type=["\']password["\'][^>]*/?>.*?</form>',
    re.IGNORECASE | re.DOTALL,
)
LOGIN_URL_RE = re.compile(
    r'(?:href|action|src)\s*=\s*["\']([^"\']*(?:login|signin|sign-in|log-in|auth|sso|oauth|cas|saml|adfs|account)[^"\']*)["\']',
    re.IGNORECASE,
)
LOGIN_TITLE_RE = re.compile(
    r'<title[^>]*>([^<]*(?:login|sign\s*in|log\s*in|authenticate|sso)[^<]*)</title>',
    re.IGNORECASE,
)
LOGIN_HEADING_RE = re.compile(
    r'<h[1-3][^>]*>([^<]*(?:login|sign\s*in|log\s*in|welcome\s*back|enter\s*your\s*credentials)[^<]*)</h[1-3]>',
    re.IGNORECASE,
)

# JS config objects
JS_CONFIG_RE = re.compile(
    r'window\.(config|env|__APP_CONFIG__|__INITIAL_STATE__|__NEXT_DATA__|__NUXT__)\s*=\s*(\{[^;]{1,5000})',
    re.IGNORECASE,
)

# Meta author
META_AUTHOR_RE = re.compile(
    r'<meta\s+(?:name=["\']author["\']\s+content=["\']([^"\']+)["\']|content=["\']([^"\']+)["\']\s+name=["\']author["\'])',
    re.IGNORECASE,
)

# Schema.org name
SCHEMA_NAME_RE = re.compile(
    r'"name"\s*:\s*"([^"]{2,60})"',
)


class TextExtractor(HTMLParser):
    """Strip HTML tags and extract visible text content."""

    def __init__(self):
        super().__init__()
        self.text_parts: List[str] = []
        self._skip = False
        self._skip_tags = {'script', 'style', 'noscript', 'svg', 'head'}

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self._skip_tags:
            self._skip = True

    def handle_endtag(self, tag):
        if tag.lower() in self._skip_tags:
            self._skip = False

    def handle_data(self, data):
        if not self._skip:
            stripped = data.strip()
            if stripped:
                self.text_parts.append(stripped)

    def get_text(self) -> str:
        return ' '.join(self.text_parts)


class CommentExtractor(HTMLParser):
    """Extract HTML comments."""

    def __init__(self):
        super().__init__()
        self.comments: List[str] = []

    def handle_comment(self, data):
        stripped = data.strip()
        if stripped:
            self.comments.append(stripped)


class HiddenInputExtractor(HTMLParser):
    """Extract hidden input fields."""

    def __init__(self):
        super().__init__()
        self.inputs: List[Dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'input':
            attr_dict = dict(attrs)
            if attr_dict.get('type', '').lower() == 'hidden':
                name = attr_dict.get('name', '')
                value = attr_dict.get('value', '')
                if name:
                    self.inputs.append({'name': name, 'value': value})


class ContentAnalyzer:
    """
    Analyze DOM snapshot and page content to extract intelligence.
    Accepts the dom_snapshot string and optionally a Playwright Page object
    for JS evaluation.
    """

    def __init__(self, dom_snapshot: str, page=None):
        self.dom_snapshot = dom_snapshot or ''
        self.page = page

    async def analyze(self) -> Dict[str, Any]:
        """Run all extraction routines and return structured data."""
        interesting_files = await self._extract_interesting_files()

        # Extract metadata from downloadable files (PDFs, images, docs)
        file_metadata = []
        if interesting_files and self.page:
            try:
                from metadata_extractor import extract_file_metadata
                file_metadata = await extract_file_metadata(
                    interesting_files, self.page.url, self.page, max_files=20,
                )
            except Exception as e:
                logger.warning("Metadata extraction failed: %s", e)

        result = {
            'emails': self._extract_emails(),
            'names': self._extract_names(),
            'internal_paths': self._extract_internal_paths(),
            'api_endpoints': self._extract_api_endpoints(),
            'exposed_keys': self._extract_exposed_keys(),
            'tech_indicators': self._extract_tech_indicators(),
            'comments': self._extract_sensitive_comments(),
            'hidden_inputs': self._extract_hidden_inputs(),
            'js_configs': await self._extract_js_configs(),
            'interesting_files': interesting_files,
            'file_metadata': file_metadata,
            'login_pages': self._extract_login_pages(),
            'word_corpus': self._extract_word_corpus(),
        }

        counts = {k: len(v) if isinstance(v, list) else (len(v) if isinstance(v, dict) else 0)
                  for k, v in result.items() if k != 'word_corpus'}
        counts['word_corpus_length'] = len(result.get('word_corpus', '') or '')
        logger.info("Content analysis complete: %s", counts)

        return result

    def _extract_emails(self) -> List[str]:
        raw = EMAIL_RE.findall(self.dom_snapshot)
        filtered = []
        seen = set()
        for email in raw:
            lower = email.lower()
            if lower in seen:
                continue
            if EMAIL_FALSE_POSITIVES.search(email):
                continue
            # Skip common image/font file patterns
            if any(lower.endswith(ext) for ext in ('.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.css')):
                continue
            seen.add(lower)
            filtered.append(email)
        return filtered[:500]  # cap

    def _extract_names(self) -> List[str]:
        names = []
        seen = set()

        # Meta author
        for m in META_AUTHOR_RE.finditer(self.dom_snapshot):
            name = (m.group(1) or m.group(2) or '').strip()
            if name and name.lower() not in seen:
                seen.add(name.lower())
                names.append(name)

        # Schema.org names (simple heuristic - skip URLs and long strings)
        for m in SCHEMA_NAME_RE.finditer(self.dom_snapshot):
            name = m.group(1).strip()
            if (name and name.lower() not in seen
                    and not name.startswith('http')
                    and len(name) < 60
                    and ' ' in name):  # likely a person/org name
                seen.add(name.lower())
                names.append(name)

        return names[:200]

    def _extract_internal_paths(self) -> List[str]:
        paths = set()

        # From HTML attributes
        for m in INTERNAL_PATH_RE.finditer(self.dom_snapshot):
            path = m.group(1)
            if not self._is_static_asset(path):
                paths.add(path)

        # From JS string literals
        for m in JS_STRING_PATH_RE.finditer(self.dom_snapshot):
            path = m.group(1)
            if not self._is_static_asset(path) and len(path) > 3:
                paths.add(path)

        return sorted(paths)[:1000]

    def _extract_api_endpoints(self) -> List[str]:
        endpoints = set()
        for m in API_ENDPOINT_RE.finditer(self.dom_snapshot):
            endpoints.add(m.group(1))
        return sorted(endpoints)[:500]

    def _extract_exposed_keys(self) -> List[Dict[str, str]]:
        keys = []
        seen = set()
        for pattern, key_type in SECRET_PATTERNS:
            for m in pattern.finditer(self.dom_snapshot):
                value = m.group(1) if m.lastindex else m.group(0)
                if value not in seen:
                    seen.add(value)
                    # Redact middle portion for storage safety
                    display = value[:4] + '...' + value[-4:] if len(value) > 12 else value[:4] + '...'
                    keys.append({
                        'type': key_type,
                        'value_preview': display,
                        'full_match': m.group(0)[:200],
                    })
        return keys[:100]

    def _extract_tech_indicators(self) -> List[Dict[str, str]]:
        indicators = []
        seen = set()
        for pattern, tech_type in TECH_PATTERNS:
            for m in pattern.finditer(self.dom_snapshot):
                value = m.group(1) if m.lastindex else m.group(0)
                key = f"{tech_type}:{value}"
                if key not in seen:
                    seen.add(key)
                    indicators.append({'type': tech_type, 'value': value[:200]})
        return indicators[:100]

    def _extract_sensitive_comments(self) -> List[Dict[str, str]]:
        extractor = CommentExtractor()
        try:
            extractor.feed(self.dom_snapshot)
        except Exception:
            pass

        sensitive = []
        for comment in extractor.comments:
            if SENSITIVE_COMMENT_RE.search(comment):
                sensitive.append({
                    'content': comment[:500],
                    'keywords': [w for w in SENSITIVE_COMMENT_RE.findall(comment)],
                })
        return sensitive[:200]

    def _extract_hidden_inputs(self) -> List[Dict[str, str]]:
        extractor = HiddenInputExtractor()
        try:
            extractor.feed(self.dom_snapshot)
        except Exception:
            pass
        return extractor.inputs[:200]

    async def _extract_js_configs(self) -> Dict[str, Any]:
        configs = {}

        # From DOM snapshot
        for m in JS_CONFIG_RE.finditer(self.dom_snapshot):
            var_name = m.group(1)
            raw_json = m.group(2)
            try:
                parsed = json.loads(raw_json)
                configs[var_name] = parsed
            except json.JSONDecodeError:
                # Store raw if can't parse (truncated)
                configs[var_name] = raw_json[:2000]

        # From page JS evaluation if available
        if self.page:
            try:
                page_configs = await self.page.evaluate("""() => {
                    const result = {};
                    const keys = ['config', 'env', '__APP_CONFIG__', '__INITIAL_STATE__',
                                  '__NEXT_DATA__', '__NUXT__'];
                    for (const k of keys) {
                        if (window[k] !== undefined) {
                            try {
                                result[k] = JSON.parse(JSON.stringify(window[k]));
                            } catch(e) {}
                        }
                    }
                    return result;
                }""")
                for k, v in (page_configs or {}).items():
                    if k not in configs:
                        configs[k] = v
            except Exception as e:
                logger.debug("JS config evaluation failed: %s", e)

        return configs

    def _extract_login_pages(self) -> List[Dict[str, Any]]:
        """Detect login pages by analyzing forms, URLs, and page content indicators."""
        login_pages = []
        seen = set()

        # 1. Forms with password fields (strongest signal)
        password_inputs = re.findall(
            r'<input[^>]*type=["\']password["\'][^>]*/?>',
            self.dom_snapshot, re.IGNORECASE,
        )
        if password_inputs:
            # Extract form action if present
            form_actions = re.findall(
                r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(?:(?!</form>).)*?'
                r'<input[^>]*type=["\']password["\']',
                self.dom_snapshot, re.IGNORECASE | re.DOTALL,
            )
            # Extract username/email fields near password fields
            username_fields = re.findall(
                r'<input[^>]*(?:name|id)=["\']([^"\']*(?:user|login|email|account|name)[^"\']*)["\']',
                self.dom_snapshot, re.IGNORECASE,
            )
            entry = {
                'type': 'password_form',
                'url': self.page.url if self.page else '',
                'form_actions': list(set(form_actions))[:5],
                'password_field_count': len(password_inputs),
                'username_fields': list(set(username_fields))[:10],
                'confidence': 'high',
            }
            key = entry['url'] or 'password_form'
            if key not in seen:
                seen.add(key)
                login_pages.append(entry)

        # 2. Login-related URLs found in links
        for m in LOGIN_URL_RE.finditer(self.dom_snapshot):
            url = m.group(1).strip()
            if url and url not in seen and not url.startswith(('#', 'javascript:')):
                seen.add(url)
                login_pages.append({
                    'type': 'login_link',
                    'url': url,
                    'confidence': 'medium',
                })

        # 3. Title or heading indicates login page
        for pattern, indicator_type in [
            (LOGIN_TITLE_RE, 'login_title'),
            (LOGIN_HEADING_RE, 'login_heading'),
        ]:
            for m in pattern.finditer(self.dom_snapshot):
                text = m.group(1).strip()
                page_url = self.page.url if self.page else ''
                key = f"{indicator_type}:{page_url}"
                if key not in seen:
                    seen.add(key)
                    login_pages.append({
                        'type': indicator_type,
                        'url': page_url,
                        'indicator_text': text[:200],
                        'confidence': 'high' if indicator_type == 'login_title' else 'medium',
                    })

        # 4. Common auth endpoints in JS/HTML
        auth_endpoints = re.findall(
            r'["\'](/(?:api/)?(?:auth|login|signin|token|session|oauth)[/a-zA-Z0-9_.?&=-]*)["\']',
            self.dom_snapshot, re.IGNORECASE,
        )
        for ep in set(auth_endpoints):
            if ep not in seen:
                seen.add(ep)
                login_pages.append({
                    'type': 'auth_endpoint',
                    'url': ep,
                    'confidence': 'low',
                })

        return login_pages[:100]

    def _extract_word_corpus(self) -> str:
        extractor = TextExtractor()
        try:
            extractor.feed(self.dom_snapshot)
        except Exception:
            pass
        return extractor.get_text()[:500000]  # cap at 500KB

    async def _extract_interesting_files(self) -> List[Dict[str, str]]:
        """Extract references to non-web files (documents, configs, backups, robots.txt)."""
        files = []
        seen = set()

        # Interesting file extensions to flag
        interesting_exts = (
            '.pdf', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.xml', '.json', '.yaml', '.yml', '.conf', '.config', '.cfg',
            '.ini', '.env', '.bak', '.backup', '.old', '.orig', '.sql', '.db',
            '.sqlite', '.log', '.zip', '.tar', '.gz', '.rar', '.7z',
            '.key', '.pem', '.crt', '.cer', '.p12', '.pfx',
            '.sh', '.bat', '.ps1', '.py', '.rb', '.pl',
            '.htaccess', '.htpasswd', '.DS_Store',
        )
        # Interesting filenames (regardless of extension)
        interesting_names = (
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            'security.txt', '.well-known/security.txt', 'humans.txt',
            'web.config', 'wp-config.php', '.env', '.git/config',
            'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
            'Dockerfile', 'docker-compose.yml', '.gitignore', 'Makefile',
            'phpinfo.php', 'info.php', 'test.php', 'admin.php',
            'server-status', 'server-info', '.svn/entries',
        )

        all_paths_re = re.compile(
            r'(?:href|src|action|data-[\w-]+)\s*=\s*["\']([^"\']+)["\']',
        )

        for m in all_paths_re.finditer(self.dom_snapshot):
            path = m.group(1).strip()
            lower = path.lower()

            # Check by extension
            is_interesting = any(lower.endswith(ext) for ext in interesting_exts)
            # Check by filename
            if not is_interesting:
                basename = lower.rstrip('/').split('/')[-1] if '/' in lower else lower
                is_interesting = basename in interesting_names or any(
                    lower.endswith('/' + n) or lower == n for n in interesting_names
                )

            if is_interesting and path not in seen:
                seen.add(path)
                # Categorize the file
                cat = 'document'
                if any(lower.endswith(e) for e in ('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.csv')):
                    cat = 'document'
                elif any(lower.endswith(e) for e in ('.zip', '.tar', '.gz', '.rar', '.7z')):
                    cat = 'archive'
                elif any(lower.endswith(e) for e in ('.bak', '.backup', '.old', '.orig', '.sql', '.db', '.sqlite')):
                    cat = 'backup'
                elif any(lower.endswith(e) for e in ('.key', '.pem', '.crt', '.cer', '.p12', '.pfx', '.env')):
                    cat = 'sensitive'
                elif any(lower.endswith(e) for e in ('.conf', '.config', '.cfg', '.ini', '.yaml', '.yml', '.json', '.xml')):
                    cat = 'config'
                elif any(lower.endswith(e) for e in ('.log', '.txt')):
                    cat = 'text'
                elif any(lower.endswith(e) for e in ('.sh', '.bat', '.ps1', '.py', '.rb', '.pl', '.php')):
                    cat = 'script'
                elif any(n in lower for n in ('robots.txt', 'sitemap.xml', 'security.txt', 'humans.txt')):
                    cat = 'meta'
                elif any(n in lower for n in ('.git', '.svn', '.htaccess', '.htpasswd', '.DS_Store')):
                    cat = 'sensitive'

                files.append({'path': path, 'category': cat})

        # Also check network logs for file downloads (via page object)
        if self.page:
            try:
                url = self.page.url
                base = '/'.join(url.split('/')[:3])  # scheme://host
                # Try to fetch robots.txt
                robots_url = f"{base}/robots.txt"
                try:
                    resp = await self.page.context.request.get(robots_url)
                    if resp.ok and 'text' in (resp.headers.get('content-type', '') or ''):
                        body = await resp.text()
                        if body and ('Disallow' in body or 'Allow' in body or 'Sitemap' in body):
                            if robots_url not in seen:
                                seen.add(robots_url)
                                files.append({'path': '/robots.txt', 'category': 'meta', 'content': body[:5000]})
                                # Extract disallowed paths as internal_paths bonus
                                for line in body.splitlines():
                                    line = line.strip()
                                    if line.lower().startswith(('disallow:', 'allow:')) and ':' in line:
                                        rpath = line.split(':', 1)[1].strip()
                                        if rpath and rpath != '/':
                                            files.append({'path': rpath, 'category': 'robots_path', 'source': 'robots.txt'})
                except Exception:
                    pass

                # Try sitemap.xml
                sitemap_url = f"{base}/sitemap.xml"
                try:
                    resp = await self.page.context.request.get(sitemap_url)
                    if resp.ok and ('xml' in (resp.headers.get('content-type', '') or '') or '<urlset' in (await resp.text())[:200]):
                        if sitemap_url not in seen:
                            seen.add(sitemap_url)
                            files.append({'path': '/sitemap.xml', 'category': 'meta'})
                except Exception:
                    pass
            except Exception as e:
                logger.debug("File discovery probes failed: %s", e)

        return files[:500]

    @staticmethod
    def _is_static_asset(path: str) -> bool:
        """Filter purely visual/layout assets (not documents or configs)."""
        static_exts = (
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map',
            '.webp', '.avif', '.mp4', '.mp3',
        )
        return path.lower().endswith(static_exts)
