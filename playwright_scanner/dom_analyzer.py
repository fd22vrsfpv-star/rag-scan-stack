"""
DOM Analysis Module
Extracts and analyzes DOM structure, forms, scripts, storage, and security configurations
"""

from typing import Dict, List
from playwright.async_api import Page


class DOMAnalyzer:
    """
    Analyzes page DOM for security-relevant information
    """

    def __init__(self, page: Page):
        self.page = page

    async def analyze(self) -> Dict:
        """
        Perform complete DOM analysis

        Returns:
            Dictionary with all analysis results
        """
        return {
            'forms': await self.extract_forms(),
            'cookies': await self.get_cookies(),
            'local_storage': await self.get_local_storage(),
            'session_storage': await self.get_session_storage(),
            'javascript_libs': await self.detect_javascript_libraries(),
            'external_scripts': await self.get_external_scripts(),
            'websockets': await self.detect_websockets(),
            'postmessage_usage': await self.detect_postmessage(),
            'window_properties': await self.get_window_properties()
        }

    async def extract_forms(self) -> List[Dict]:
        """
        Extract all forms with their fields

        Returns:
            List of form dictionaries with actions, methods, and inputs
        """
        forms = await self.page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, index) => {
                    const inputs = [];
                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        inputs.push({
                            type: input.type || input.tagName.toLowerCase(),
                            name: input.name || '',
                            id: input.id || '',
                            value: input.type === 'password' ? '[REDACTED]' : (input.value || '').substring(0, 100),
                            required: input.required || false,
                            autocomplete: input.autocomplete || ''
                        });
                    });

                    forms.push({
                        index: index,
                        action: form.action || '',
                        method: form.method || 'get',
                        name: form.name || '',
                        id: form.id || '',
                        enctype: form.enctype || '',
                        target: form.target || '',
                        selector: `form:nth-of-type(${index + 1})`,
                        inputs: inputs,
                        has_file_input: inputs.some(i => i.type === 'file'),
                        has_password_input: inputs.some(i => i.type === 'password')
                    });
                });
                return forms;
            }
        """)
        return forms

    async def get_cookies(self) -> List[Dict]:
        """
        Get all cookies with their security attributes

        Returns:
            List of cookie dictionaries
        """
        cookies = await self.page.context.cookies()
        return [
            {
                'name': cookie.get('name'),
                'value': '[REDACTED]' if len(cookie.get('value', '')) > 0 else '',
                'domain': cookie.get('domain'),
                'path': cookie.get('path'),
                'expires': cookie.get('expires', -1),
                'httpOnly': cookie.get('httpOnly', False),
                'secure': cookie.get('secure', False),
                'sameSite': cookie.get('sameSite', 'None')
            }
            for cookie in cookies
        ]

    async def get_local_storage(self) -> Dict:
        """
        Get localStorage contents (keys only for security)

        Returns:
            Dictionary of localStorage keys and value lengths
        """
        try:
            storage = await self.page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        const value = localStorage.getItem(key);
                        // Only store key and value length for security
                        items[key] = {
                            length: value ? value.length : 0,
                            hasData: value && value.length > 0
                        };
                    }
                    return items;
                }
            """)
            return storage
        except Exception as e:
            return {'error': str(e)}

    async def get_session_storage(self) -> Dict:
        """
        Get sessionStorage contents (keys only for security)

        Returns:
            Dictionary of sessionStorage keys and value lengths
        """
        try:
            storage = await self.page.evaluate("""
                () => {
                    const items = {};
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        const value = sessionStorage.getItem(key);
                        items[key] = {
                            length: value ? value.length : 0,
                            hasData: value && value.length > 0
                        };
                    }
                    return items;
                }
            """)
            return storage
        except Exception as e:
            return {'error': str(e)}

    async def detect_javascript_libraries(self) -> List[Dict]:
        """
        Detect JavaScript libraries and frameworks

        Returns:
            List of detected libraries with versions if available
        """
        libraries = await self.page.evaluate("""
            () => {
                const detected = [];

                // Check for common libraries on window object
                const checks = {
                    'jQuery': () => typeof window.jQuery !== 'undefined' ? window.jQuery.fn.jquery : null,
                    'React': () => typeof window.React !== 'undefined' ? window.React.version : null,
                    'Vue': () => typeof window.Vue !== 'undefined' ? window.Vue.version : null,
                    'Angular': () => {
                        if (typeof window.angular !== 'undefined') return window.angular.version.full;
                        if (typeof window.ng !== 'undefined') return 'Angular (version unknown)';
                        return null;
                    },
                    'Backbone': () => typeof window.Backbone !== 'undefined' ? window.Backbone.VERSION : null,
                    'Ember': () => typeof window.Ember !== 'undefined' ? window.Ember.VERSION : null,
                    'Lodash': () => typeof window._ !== 'undefined' && window._.VERSION ? window._.VERSION : null,
                    'Underscore': () => typeof window._ !== 'undefined' && !window._.VERSION ? 'detected' : null,
                    'Moment': () => typeof window.moment !== 'undefined' ? window.moment.version : null,
                    'D3': () => typeof window.d3 !== 'undefined' ? window.d3.version : null,
                    'Bootstrap': () => {
                        const el = document.querySelector('[data-bs-version]');
                        if (el) return el.getAttribute('data-bs-version');
                        if (typeof window.bootstrap !== 'undefined') return 'detected';
                        return null;
                    },
                    'Next.js': () => typeof window.__NEXT_DATA__ !== 'undefined' ? 'detected' : null,
                    'Nuxt': () => typeof window.__NUXT__ !== 'undefined' ? 'detected' : null,
                    'Svelte': () => typeof window.__SVELTE__ !== 'undefined' ? 'detected' : null
                };

                for (const [name, check] of Object.entries(checks)) {
                    try {
                        const version = check();
                        if (version) {
                            detected.push({ name, version: version.toString() });
                        }
                    } catch (e) {
                        // Ignore errors
                    }
                }

                // Check for framework-specific attributes in HTML
                if (document.querySelector('[ng-version], [ng-app]')) {
                    if (!detected.some(d => d.name === 'Angular')) {
                        detected.push({ name: 'Angular', version: 'detected in DOM' });
                    }
                }

                if (document.querySelector('[data-reactroot], [data-reactid]')) {
                    if (!detected.some(d => d.name === 'React')) {
                        detected.push({ name: 'React', version: 'detected in DOM' });
                    }
                }

                return detected;
            }
        """)
        return libraries

    async def get_external_scripts(self) -> List[str]:
        """
        Get all external script sources

        Returns:
            List of external script URLs
        """
        scripts = await self.page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script[src]').forEach(script => {
                    const src = script.src;
                    // Only include external scripts (different origin)
                    if (src && !src.startsWith(window.location.origin)) {
                        scripts.push(src);
                    }
                });
                return scripts;
            }
        """)
        return scripts

    async def detect_websockets(self) -> List[Dict]:
        """
        Detect WebSocket connections (via window inspection)

        Returns:
            List of WebSocket information
        """
        websockets = await self.page.evaluate("""
            () => {
                const ws = [];
                // Check if WebSocket was used
                if (typeof window.WebSocket !== 'undefined') {
                    ws.push({
                        available: true,
                        note: 'WebSocket API is available (active connections cannot be enumerated for security)'
                    });
                }
                return ws;
            }
        """)
        return websockets

    async def detect_postmessage(self) -> bool:
        """
        Detect if postMessage API is used

        Returns:
            True if postMessage event listeners are registered
        """
        has_postmessage = await self.page.evaluate("""
            () => {
                // Check if there are message event listeners
                const listeners = window.getEventListeners ? window.getEventListeners(window) : {};
                return listeners.message && listeners.message.length > 0;
            }
        """)
        return has_postmessage

    async def get_window_properties(self) -> List[str]:
        """
        Get interesting properties from window object

        Returns:
            List of interesting window property names
        """
        properties = await self.page.evaluate("""
            () => {
                const props = [];
                const interesting = [
                    'jQuery', '$', 'React', 'ReactDOM', 'Vue', 'Angular', 'angular', 'ng',
                    'Backbone', 'Ember', '_', 'moment', 'd3', 'bootstrap',
                    '__NEXT_DATA__', '__NUXT__', '__SVELTE__',
                    '__REACT_DEVTOOLS_GLOBAL_HOOK__', '__VUE_DEVTOOLS_GLOBAL_HOOK__'
                ];

                for (const prop of interesting) {
                    if (prop in window) {
                        props.push(prop);
                    }
                }

                return props;
            }
        """)
        return properties

    async def get_dom_snapshot(self) -> str:
        """
        Get full HTML snapshot of the page

        Returns:
            HTML string (limited to reasonable size)
        """
        try:
            html = await self.page.content()
            # Limit size to avoid huge snapshots
            max_size = 1_000_000  # 1MB
            if len(html) > max_size:
                html = html[:max_size] + '\n... (truncated)'
            return html
        except Exception as e:
            return f"Error getting snapshot: {str(e)}"

    async def analyze_security_headers(self, response=None) -> Dict:
        """
        Extract and categorize security-related headers

        Args:
            response: Optional pre-fetched response object (avoids re-navigation)

        Returns:
            Dictionary of security headers
        """
        if response is None:
            response = await self.page.goto(self.page.url)
        if not response:
            return {}

        headers = await response.all_headers()

        security_headers = {}
        security_keys = [
            'content-security-policy', 'content-security-policy-report-only',
            'strict-transport-security', 'x-frame-options', 'x-content-type-options',
            'x-xss-protection', 'referrer-policy', 'permissions-policy',
            'feature-policy', 'cross-origin-embedder-policy',
            'cross-origin-opener-policy', 'cross-origin-resource-policy',
            'access-control-allow-origin', 'access-control-allow-credentials',
            'access-control-allow-methods', 'access-control-allow-headers',
            # Software version leak headers (for detected_software view)
            'server', 'x-powered-by', 'x-aspnet-version', 'x-generator',
        ]

        for key in security_keys:
            if key in headers:
                security_headers[key] = headers[key]

        return security_headers

    async def check_mixed_content(self) -> bool:
        """
        Check if page has mixed content (HTTP resources on HTTPS page)

        Returns:
            True if mixed content detected
        """
        if not self.page.url.startswith('https://'):
            return False

        mixed = await self.page.evaluate("""
            () => {
                // Check for HTTP resources
                const resources = [
                    ...document.querySelectorAll('script[src]'),
                    ...document.querySelectorAll('link[href]'),
                    ...document.querySelectorAll('img[src]'),
                    ...document.querySelectorAll('iframe[src]')
                ];

                for (const res of resources) {
                    const url = res.src || res.href;
                    if (url && url.startsWith('http://')) {
                        return true;
                    }
                }
                return false;
            }
        """)
        return mixed

    async def get_cors_config(self) -> Dict:
        """
        Get CORS configuration from headers

        Returns:
            Dictionary with CORS settings
        """
        response = await self.page.goto(self.page.url)
        if not response:
            return {'enabled': False}

        headers = await response.all_headers()

        return {
            'enabled': 'access-control-allow-origin' in headers,
            'allow_origin': headers.get('access-control-allow-origin'),
            'allow_credentials': headers.get('access-control-allow-credentials'),
            'allow_methods': headers.get('access-control-allow-methods'),
            'allow_headers': headers.get('access-control-allow-headers'),
            'expose_headers': headers.get('access-control-expose-headers'),
            'max_age': headers.get('access-control-max-age')
        }
