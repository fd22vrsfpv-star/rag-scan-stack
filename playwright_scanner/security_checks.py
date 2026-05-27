"""
Security checks for browser-based vulnerabilities
Detects XSS, CSRF, clickjacking, mixed content, and other client-side issues
"""

from typing import List, Dict, Optional
import re


class SecurityChecker:
    """
    Performs various client-side security checks on web pages
    """

    def __init__(self):
        self.findings = []

    def check_clickjacking(self, headers: Dict[str, str], url: str) -> Optional[Dict]:
        """
        Check for clickjacking vulnerabilities (missing X-Frame-Options or CSP frame-ancestors)

        Args:
            headers: HTTP response headers
            url: Page URL

        Returns:
            Finding dict if vulnerable, None otherwise
        """
        x_frame_options = headers.get('x-frame-options', '').lower()
        csp = headers.get('content-security-policy', '').lower()

        has_xfo_protection = x_frame_options in ['deny', 'sameorigin']
        has_csp_protection = 'frame-ancestors' in csp and ("'none'" in csp or "'self'" in csp)

        if not has_xfo_protection and not has_csp_protection:
            return {
                'finding_type': 'clickjacking',
                'severity': 'medium',
                'title': 'Missing Clickjacking Protection',
                'description': (
                    'Page lacks both X-Frame-Options and CSP frame-ancestors directive, '
                    'making it vulnerable to clickjacking attacks.'
                ),
                'evidence': f"X-Frame-Options: {x_frame_options or 'missing'}, CSP: {csp[:100] if csp else 'missing'}",
                'location': url,
                'remediation': (
                    "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors \\'none\\'' header"
                ),
                'cwe': ['CWE-1021'],
                'owasp_category': 'A01:2021-Broken Access Control',
                'confidence': 0.9
            }
        return None

    def check_mixed_content(self, url: str, resources: List[Dict]) -> List[Dict]:
        """
        Check for mixed content (HTTP resources on HTTPS pages)

        Args:
            url: Page URL
            resources: List of loaded resources with URLs

        Returns:
            List of findings
        """
        findings = []

        if not url.startswith('https://'):
            return findings

        http_resources = [r for r in resources if r.get('url', '').startswith('http://')]

        if http_resources:
            # Group by type
            scripts = [r for r in http_resources if r.get('type') in ['script', 'xhr', 'fetch']]
            stylesheets = [r for r in http_resources if r.get('type') == 'stylesheet']
            images = [r for r in http_resources if r.get('type') == 'image']
            other = [r for r in http_resources if r not in scripts + stylesheets + images]

            if scripts:
                findings.append({
                    'finding_type': 'mixed-content',
                    'severity': 'high',
                    'title': 'Mixed Content - Active Resources',
                    'description': (
                        f'HTTPS page loads {len(scripts)} HTTP script(s), '
                        'allowing MITM attacks to inject malicious code.'
                    ),
                    'evidence': ', '.join([r['url'][:100] for r in scripts[:3]]),
                    'location': url,
                    'remediation': 'Use HTTPS URLs for all scripts and active resources',
                    'cwe': ['CWE-311'],
                    'owasp_category': 'A02:2021-Cryptographic Failures',
                    'confidence': 1.0
                })

            if stylesheets:
                findings.append({
                    'finding_type': 'mixed-content',
                    'severity': 'medium',
                    'title': 'Mixed Content - Stylesheets',
                    'description': f'HTTPS page loads {len(stylesheets)} HTTP stylesheet(s).',
                    'evidence': ', '.join([r['url'][:100] for r in stylesheets[:3]]),
                    'location': url,
                    'remediation': 'Use HTTPS URLs for all stylesheets',
                    'cwe': ['CWE-311'],
                    'owasp_category': 'A02:2021-Cryptographic Failures',
                    'confidence': 1.0
                })

            if images or other:
                passive_count = len(images) + len(other)
                findings.append({
                    'finding_type': 'mixed-content',
                    'severity': 'low',
                    'title': 'Mixed Content - Passive Resources',
                    'description': f'HTTPS page loads {passive_count} HTTP passive resource(s) (images, media).',
                    'evidence': f"Examples: {', '.join([r['url'][:80] for r in (images + other)[:2]])}",
                    'location': url,
                    'remediation': 'Use HTTPS URLs for all resources',
                    'cwe': ['CWE-311'],
                    'owasp_category': 'A02:2021-Cryptographic Failures',
                    'confidence': 0.9
                })

        return findings

    def check_csrf_protection(self, forms: List[Dict], url: str) -> List[Dict]:
        """
        Check forms for CSRF token protection

        Args:
            forms: List of form elements with their fields
            url: Page URL

        Returns:
            List of findings for forms without CSRF protection
        """
        findings = []

        for i, form in enumerate(forms):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = form.get('inputs', [])

            # Only check state-changing methods
            if method not in ['post', 'put', 'delete', 'patch']:
                continue

            # Look for CSRF token
            csrf_token_found = False
            csrf_token_names = [
                'csrf', 'csrf_token', 'csrftoken', '_token', 'authenticity_token', '__requestverificationtoken'
            ]

            for inp in inputs:
                name = inp.get('name', '').lower()
                if any(token_name in name for token_name in csrf_token_names):
                    csrf_token_found = True
                    break

            if not csrf_token_found:
                findings.append({
                    'finding_type': 'csrf',
                    'severity': 'high',
                    'title': 'Missing CSRF Token',
                    'description': f'Form #{i+1} uses {method.upper()} method but lacks CSRF protection token.',
                    'evidence': f"Form action: {action}, method: {method}, inputs: {len(inputs)}",
                    'location': form.get('selector', f"form[{i}]"),
                    'remediation': 'Add CSRF token to form as hidden input field',
                    'cwe': ['CWE-352'],
                    'owasp_category': 'A01:2021-Broken Access Control',
                    'confidence': 0.7  # Lower confidence as some apps use other CSRF protection
                })

        return findings

    def check_security_headers(self, headers: Dict[str, str], url: str) -> List[Dict]:
        """
        Check for missing or misconfigured security headers

        Args:
            headers: HTTP response headers
            url: Page URL

        Returns:
            List of findings for missing/weak headers
        """
        findings = []

        # Normalize header keys to lowercase
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check Content-Security-Policy
        if 'content-security-policy' not in headers_lower:
            findings.append({
                'finding_type': 'missing-security-header',
                'severity': 'medium',
                'title': 'Missing Content-Security-Policy Header',
                'description': 'Page lacks CSP header, increasing XSS attack surface.',
                'evidence': 'Content-Security-Policy header not found',
                'location': url,
                'remediation': "Add Content-Security-Policy header with restrictive policy",
                'cwe': ['CWE-693'],
                'owasp_category': 'A03:2021-Injection',
                'confidence': 0.9
            })
        else:
            csp = headers_lower['content-security-policy'].lower()
            if 'unsafe-inline' in csp:
                findings.append({
                    'finding_type': 'weak-csp',
                    'severity': 'medium',
                    'title': 'Weak Content-Security-Policy',
                    'description': "CSP contains 'unsafe-inline', reducing XSS protection effectiveness.",
                    'evidence': csp[:200],
                    'location': url,
                    'remediation': "Remove 'unsafe-inline' and use nonces or hashes for inline scripts",
                    'cwe': ['CWE-693'],
                    'owasp_category': 'A03:2021-Injection',
                    'confidence': 0.8
                })

        # Check Strict-Transport-Security (for HTTPS sites)
        if url.startswith('https://'):
            if 'strict-transport-security' not in headers_lower:
                findings.append({
                    'finding_type': 'missing-security-header',
                    'severity': 'medium',
                    'title': 'Missing Strict-Transport-Security Header',
                    'description': 'HTTPS site lacks HSTS header, vulnerable to downgrade attacks.',
                    'evidence': 'Strict-Transport-Security header not found',
                    'location': url,
                    'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
                    'cwe': ['CWE-319'],
                    'owasp_category': 'A02:2021-Cryptographic Failures',
                    'confidence': 0.9
                })

        # Check X-Content-Type-Options
        if 'x-content-type-options' not in headers_lower:
            findings.append({
                'finding_type': 'missing-security-header',
                'severity': 'low',
                'title': 'Missing X-Content-Type-Options Header',
                'description': 'Missing header allows MIME-sniffing attacks.',
                'evidence': 'X-Content-Type-Options header not found',
                'location': url,
                'remediation': 'Add X-Content-Type-Options: nosniff',
                'cwe': ['CWE-693'],
                'owasp_category': 'A05:2021-Security Misconfiguration',
                'confidence': 0.8
            })

        # Check X-XSS-Protection (legacy but still useful)
        xss_protection = headers_lower.get('x-xss-protection', '')
        if not xss_protection or xss_protection == '0':
            findings.append({
                'finding_type': 'missing-security-header',
                'severity': 'low',
                'title': 'Missing or Disabled X-XSS-Protection',
                'description': 'XSS filter not enabled for legacy browsers.',
                'evidence': f"X-XSS-Protection: {xss_protection or 'missing'}",
                'location': url,
                'remediation': 'Add X-XSS-Protection: 1; mode=block',
                'cwe': ['CWE-79'],
                'owasp_category': 'A03:2021-Injection',
                'confidence': 0.7
            })

        # Check Referrer-Policy
        if 'referrer-policy' not in headers_lower:
            findings.append({
                'finding_type': 'missing-security-header',
                'severity': 'info',
                'title': 'Missing Referrer-Policy Header',
                'description': 'Missing header may leak sensitive data in referrer.',
                'evidence': 'Referrer-Policy header not found',
                'location': url,
                'remediation': 'Add Referrer-Policy: no-referrer or strict-origin-when-cross-origin',
                'cwe': ['CWE-200'],
                'owasp_category': 'A01:2021-Broken Access Control',
                'confidence': 0.6
            })

        # Check Permissions-Policy (formerly Feature-Policy)
        if 'permissions-policy' not in headers_lower and 'feature-policy' not in headers_lower:
            findings.append({
                'finding_type': 'missing-security-header',
                'severity': 'info',
                'title': 'Missing Permissions-Policy Header',
                'description': 'Missing header allows unrestricted use of browser features.',
                'evidence': 'Permissions-Policy header not found',
                'location': url,
                'remediation': 'Add Permissions-Policy to restrict camera, microphone, geolocation, etc.',
                'cwe': ['CWE-693'],
                'owasp_category': 'A05:2021-Security Misconfiguration',
                'confidence': 0.5
            })

        return findings

    def check_sensitive_data_exposure(
        self, cookies: List[Dict], local_storage: Dict, session_storage: Dict, url: str
    ) -> List[Dict]:
        """
        Check for sensitive data in cookies and storage

        Args:
            cookies: Browser cookies
            local_storage: localStorage contents
            session_storage: sessionStorage contents
            url: Page URL

        Returns:
            List of findings
        """
        findings = []

        # Patterns that might indicate sensitive data
        sensitive_patterns = [
            r'(password|passwd|pwd)',
            r'(api[_-]?key|apikey)',
            r'(secret|token)',
            r'(credit[_-]?card|cc[_-]?number)',
            r'(ssn|social[_-]?security)',
            r'(private[_-]?key|priv[_-]?key)'
        ]

        # Check cookies
        insecure_cookies = []
        sensitive_cookies = []

        for cookie in cookies:
            name = cookie.get('name', '').lower()
            # value = cookie.get('value', '')  # Reserved for future use
            secure = cookie.get('secure', False)
            http_only = cookie.get('httpOnly', False)
            # same_site = cookie.get('sameSite', 'None')  # Reserved for future use

            # Check for sensitive patterns in name
            if any(re.search(pattern, name, re.IGNORECASE) for pattern in sensitive_patterns):
                sensitive_cookies.append(cookie)

                if not secure and url.startswith('https://'):
                    insecure_cookies.append(f"{name} (missing Secure flag)")

                if not http_only and 'session' in name or 'token' in name:
                    findings.append({
                        'finding_type': 'insecure-cookie',
                        'severity': 'medium',
                        'title': 'Sensitive Cookie Without HttpOnly Flag',
                        'description': (
                            f'Cookie "{name}" appears sensitive but lacks HttpOnly flag, '
                            'making it accessible to JavaScript.'
                        ),
                        'evidence': f"Cookie: {name}, HttpOnly: {http_only}, Secure: {secure}",
                        'location': url,
                        'remediation': 'Set HttpOnly and Secure flags on sensitive cookies',
                        'cwe': ['CWE-1004'],
                        'owasp_category': 'A05:2021-Security Misconfiguration',
                        'confidence': 0.7
                    })

        if insecure_cookies:
            findings.append({
                'finding_type': 'insecure-cookie',
                'severity': 'medium',
                'title': 'Sensitive Cookies Without Secure Flag',
                'description': f'{len(insecure_cookies)} sensitive cookie(s) lack Secure flag on HTTPS site.',
                'evidence': ', '.join(insecure_cookies[:3]),
                'location': url,
                'remediation': 'Set Secure flag on all cookies for HTTPS sites',
                'cwe': ['CWE-614'],
                'owasp_category': 'A05:2021-Security Misconfiguration',
                'confidence': 0.8
            })

        # Check localStorage
        sensitive_storage_keys = []
        for key in local_storage.keys():
            if any(re.search(pattern, key, re.IGNORECASE) for pattern in sensitive_patterns):
                sensitive_storage_keys.append(key)

        if sensitive_storage_keys:
            findings.append({
                'finding_type': 'sensitive-data-exposure',
                'severity': 'high',
                'title': 'Sensitive Data in localStorage',
                'description': (
                    f'Found {len(sensitive_storage_keys)} potentially sensitive key(s) in localStorage, '
                    'which is accessible to JavaScript and persists across sessions.'
                ),
                'evidence': ', '.join(sensitive_storage_keys[:5]),
                'location': url,
                'remediation': (
                    'Avoid storing sensitive data in localStorage; use secure, httpOnly cookies or '
                    'session storage with proper encryption'
                ),
                'cwe': ['CWE-922'],
                'owasp_category': 'A02:2021-Cryptographic Failures',
                'confidence': 0.6
            })

        return findings

    def check_cors_misconfiguration(self, headers: Dict[str, str], url: str) -> Optional[Dict]:
        """
        Check for dangerous CORS configurations

        Args:
            headers: HTTP response headers
            url: Page URL

        Returns:
            Finding dict if vulnerable, None otherwise
        """
        acao = headers.get('access-control-allow-origin', '')
        acac = headers.get('access-control-allow-credentials', '').lower()

        # Wildcard with credentials is dangerous
        if acao == '*' and acac == 'true':
            return {
                'finding_type': 'cors-misconfiguration',
                'severity': 'high',
                'title': 'Dangerous CORS Configuration',
                'description': (
                    'CORS allows all origins (*) with credentials, '
                    'enabling any website to make authenticated requests.'
                ),
                'evidence': "Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                'location': url,
                'remediation': 'Use specific origins instead of wildcard, or disable credentials',
                'cwe': ['CWE-942'],
                'owasp_category': 'A05:2021-Security Misconfiguration',
                'confidence': 0.95
            }

        # Reflecting Origin header is also dangerous
        if acac == 'true' and acao and acao != '*':
            # This is a simplification; in real checks we'd need to compare with request Origin
            return {
                'finding_type': 'cors-misconfiguration',
                'severity': 'medium',
                'title': 'CORS May Reflect Origin Header',
                'description': (
                    'CORS allows credentials and sets specific origin, which might be reflected from request.'
                ),
                'evidence': f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: true",
                'location': url,
                'remediation': 'Validate Origin header against whitelist before reflecting',
                'cwe': ['CWE-942'],
                'owasp_category': 'A05:2021-Security Misconfiguration',
                'confidence': 0.5  # Lower confidence without seeing actual request
            }

        return None

    def detect_js_frameworks(self, page_content: str, window_properties: List[str]) -> List[Dict]:
        """
        Detect JavaScript frameworks and their versions

        Args:
            page_content: HTML content
            window_properties: List of properties on window object

        Returns:
            List of detected frameworks with versions
        """
        frameworks = []

        # Common framework detection patterns
        checks = {
            'React': ['React', 'ReactDOM', '__REACT'],
            'Vue': ['Vue', '__VUE__'],
            'Angular': ['ng', 'angular', 'getAllAngularRootElements'],
            'jQuery': ['jQuery', '$'],
            'Backbone': ['Backbone'],
            'Ember': ['Ember'],
            'Next.js': ['__NEXT_DATA__', 'next'],
            'Nuxt': ['__NUXT__'],
            'Svelte': ['__SVELTE__']
        }

        for framework, props in checks.items():
            if any(prop in window_properties for prop in props):
                frameworks.append({'name': framework, 'detected': True})

        # Check for framework-specific patterns in HTML
        if 'ng-version' in page_content or 'ng-app' in page_content:
            if not any(f['name'] == 'Angular' for f in frameworks):
                frameworks.append({'name': 'Angular', 'detected': True})

        if 'data-reactroot' in page_content or 'data-react' in page_content:
            if not any(f['name'] == 'React' for f in frameworks):
                frameworks.append({'name': 'React', 'detected': True})

        return frameworks
