"""
Playwright-ZAP Integration Bridge
Configures Playwright to proxy through ZAP for comprehensive security scanning
"""

import os
import time
from typing import Optional, Dict, List
from zapv2 import ZAPv2
import requests


class ZAPBridge:
    """
    Bridges Playwright browser automation with OWASP ZAP proxy
    """

    def __init__(
        self,
        zap_addr: str = None,
        zap_port: int = None,
        zap_api_key: str = None
    ):
        self.zap_addr = zap_addr or os.environ.get("ZAP_ADDR", "zap")
        self.zap_port = zap_port or int(os.environ.get("ZAP_PORT", "8090"))
        self.zap_api_key = zap_api_key or os.environ.get("ZAP_API_KEY", "changeme")

        self.zap_url = f"http://{self.zap_addr}:{self.zap_port}"
        self.proxy_url = f"http://{self.zap_addr}:{self.zap_port}"

        self.zap = ZAPv2(
            apikey=self.zap_api_key,
            proxies={'http': self.zap_url, 'https': self.zap_url}
        )

    def get_proxy_config(self) -> Dict:
        """
        Get proxy configuration for Playwright

        Returns:
            Dictionary with proxy settings
        """
        return {
            'server': self.proxy_url,
            'bypass': 'localhost,127.0.0.1'  # Don't proxy localhost
        }

    def is_zap_ready(self, timeout: int = 60) -> bool:
        """
        Check if ZAP is ready and responding

        Args:
            timeout: Maximum seconds to wait

        Returns:
            True if ZAP is ready, False otherwise
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                response = requests.get(
                    f"{self.zap_url}/JSON/core/view/version/",
                    params={'apikey': self.zap_api_key},
                    timeout=5
                )
                if response.status_code == 200:
                    return True
            except Exception:
                time.sleep(1)
        return False

    def create_context(
        self,
        context_name: str,
        target_url: str,
        include_in_context: Optional[List[str]] = None
    ) -> str:
        """
        Create a new ZAP context for the target

        Args:
            context_name: Name for the context
            target_url: Target URL
            include_in_context: Additional URL patterns to include

        Returns:
            Context ID
        """
        try:
            # Create context
            context_id = self.zap.context.new_context(context_name)

            # Include target URL in context
            self.zap.context.include_in_context(context_name, f"{target_url}.*")

            if include_in_context:
                for pattern in include_in_context:
                    self.zap.context.include_in_context(context_name, pattern)

            return context_id
        except Exception as e:
            print(f"Error creating ZAP context: {e}")
            return ""

    def _ensure_csrf_auth_script(self):
        """Load the bundled generic CSRF-login auth script into ZAP once. Returns
        the script name, or None if no JS engine / load failed."""
        name = "csrf_form_auth"
        try:
            existing = self.zap.script.list_scripts or []
            if any((sc.get("name") == name) for sc in existing):
                return name
            engines = self.zap.script.list_engines or []
            js = next((e for e in engines if any(t in e.lower()
                       for t in ("graal", "ecmascript", "nashorn", "javascript"))), None)
            if not js:
                print("ZAP has no JS script engine — CSRF script auth unavailable")
                return None
            r = self.zap.script.load(
                scriptname=name, scripttype="authentication",
                scriptengine=js, filename="/home/zap/csrf_auth.js")
            if str(r).upper() != "OK":
                print(f"ZAP CSRF auth script load returned {r}")
            return name
        except Exception as e:  # noqa: BLE001
            print(f"Error loading CSRF auth script: {e}")
            return None

    def configure_script_authentication(self, context_name, context_id, auth):
        """Script-based auth for login forms that carry an anti-CSRF token
        (DVWA user_token, Django csrfmiddlewaretoken, ...). The bundled script
        GETs the login page, scrapes the token, and POSTs the login with it.
        auth needs: login_url, csrf_field, login_data (with {%username%}/
        {%password%}/{%csrf%}), username, password. Returns the ZAP user id."""
        try:
            import urllib.parse as _up
            name = self._ensure_csrf_auth_script()
            if not name:
                return None
            login_url = (auth.get("login_url") or "").strip()
            login_data = (auth.get("login_data") or "").strip()
            csrf_field = (auth.get("csrf_field") or "user_token").strip()
            username = auth.get("username") or ""
            password = auth.get("password") or ""
            if not (login_url and login_data and username):
                return None
            self.zap.sessionManagement.set_session_management_method(
                context_id, "cookieBasedSessionManagement", "")
            params = ("scriptName=" + _up.quote(name, safe="")
                      + "&loginUrl=" + _up.quote(login_url, safe="")
                      + "&csrfField=" + _up.quote(csrf_field, safe="")
                      + "&loginData=" + _up.quote(login_data, safe=""))
            self.zap.authentication.set_authentication_method(
                context_id, "scriptBasedAuthentication", params)
            if auth.get("logged_in_regex"):
                self.zap.authentication.set_logged_in_indicator(context_id, auth["logged_in_regex"])
            if auth.get("logged_out_regex"):
                self.zap.authentication.set_logged_out_indicator(context_id, auth["logged_out_regex"])
            user_id = self.zap.users.new_user(context_id, username)
            self.zap.users.set_authentication_credentials(
                context_id, user_id,
                "username=" + _up.quote(username, safe="")
                + "&password=" + _up.quote(password, safe=""))
            self.zap.users.set_user_enabled(context_id, user_id, "true")
            self.zap.forcedUser.set_forced_user(context_id, user_id)
            self.zap.forcedUser.set_forced_user_mode_enabled("true")
            print(f"ZAP CSRF script-auth configured for {context_name} (field {csrf_field})")
            return user_id
        except Exception as e:  # noqa: BLE001
            print(f"Error configuring ZAP script authentication: {e}")
            return None

    def configure_authentication(self, context_name, context_id, auth):
        """FORM-BASED authentication for ANY app with a login form, so the spider
        and active scan run as a logged-in user (not hardcoded to one app).

        If the login carries an anti-CSRF token (auth_type == "csrf", or a
        csrf_field is given), this delegates to script-based auth instead.

        auth keys:
          login_url        the form action URL that receives the POST
          login_data       POST body with {%username%}/{%password%} placeholders,
                           e.g. "username={%username%}&password={%password%}&Login=Login"
          username / password  the credentials to substitute
          logged_in_regex  (optional) a regex present ONLY when logged in
          logged_out_regex (optional) a regex present ONLY when logged out
        Returns the ZAP user id, or None if there is not enough config."""
        # CSRF logins need the multi-step script auth (GET token -> POST).
        if str(auth.get("auth_type") or "").lower() == "csrf" or auth.get("csrf_field"):
            return self.configure_script_authentication(context_name, context_id, auth)
        try:
            import urllib.parse as _up
            login_url = (auth.get("login_url") or "").strip()
            login_data = (auth.get("login_data") or "").strip()
            username = auth.get("username") or ""
            password = auth.get("password") or ""
            if not (login_url and login_data and username):
                return None
            # cookie session so the auth cookie carries across the scan
            self.zap.sessionManagement.set_session_management_method(
                context_id, "cookieBasedSessionManagement", "")
            cfg = ("loginUrl=" + _up.quote(login_url, safe="")
                   + "&loginRequestData=" + _up.quote(login_data, safe=""))
            self.zap.authentication.set_authentication_method(
                context_id, "formBasedAuthentication", cfg)
            if auth.get("logged_in_regex"):
                self.zap.authentication.set_logged_in_indicator(
                    context_id, auth["logged_in_regex"])
            if auth.get("logged_out_regex"):
                self.zap.authentication.set_logged_out_indicator(
                    context_id, auth["logged_out_regex"])
            user_id = self.zap.users.new_user(context_id, username)
            self.zap.users.set_authentication_credentials(
                context_id, user_id,
                "username=" + _up.quote(username, safe="")
                + "&password=" + _up.quote(password, safe=""))
            self.zap.users.set_user_enabled(context_id, user_id, "true")
            self.zap.forcedUser.set_forced_user(context_id, user_id)
            self.zap.forcedUser.set_forced_user_mode_enabled("true")
            print(f"ZAP form-auth configured for context {context_name} as user {username} (id {user_id})")
            return user_id
        except Exception as e:  # noqa: BLE001
            print(f"Error configuring ZAP authentication: {e}")
            return None

    def apply_session_headers(self, headers: dict) -> int:
        """Inject static session headers (bearer/JWT Authorization, X-API-Key,
        Cookie) into EVERY ZAP request via the Replacer add-on — this is how
        token/header-authenticated apps and APIs are scanned authenticated (no
        login form). Returns how many rules were added. Best-effort."""
        n = 0
        for name, value in (headers or {}).items():
            if not name or value in (None, ""):
                continue
            try:
                self.zap.replacer.add_rule(
                    description=f"authhdr_{name}", enabled=True,
                    matchtype="REQ_HEADER", matchregex=False, matchstring=name,
                    replacement=str(value), initiators="", url="")
                n += 1
            except Exception as e:  # noqa: BLE001
                print(f"ZAP replacer add_rule failed for {name}: {e}")
        if n:
            print(f"ZAP: injected {n} session header(s) into all requests")
        return n

    def verify_authentication(self, context_id, user_id):
        """Confirm ZAP actually logged in — mirrors the pipeline path
        (web_scan.configure_zap_auth): trigger a login and read the auth state,
        where 0/empty means it never authenticated. Returns True/False, or None
        if ZAP could not tell us. This replaces the old
        `authenticated = bool(user_id)` (a user object is not a live session)."""
        try:
            self.zap.users.authenticate_as_user(context_id, user_id)
            time.sleep(3)
            state = str(self.zap.users.get_authentication_state(context_id, user_id) or "0")
            return state not in ("0", "", "None")
        except Exception as e:  # noqa: BLE001
            print(f"ZAP auth verification could not run: {e}")
            return None

    def spider_url(
        self,
        url: str,
        context_name: Optional[str] = None,
        max_depth: int = 5,
        max_duration: int = 300,
        user_id: Optional[str] = None,
        context_id: Optional[str] = None
    ) -> str:
        """
        Run ZAP spider on URL

        Args:
            url: Target URL
            context_name: Optional context to use
            max_depth: Maximum spider depth
            max_duration: Maximum spider duration in seconds

        Returns:
            Spider scan ID
        """
        try:
            if user_id is not None and context_id is not None:
                # authenticated crawl — spider as the logged-in user
                scan_id = self.zap.spider.scan_as_user(
                    context_id, user_id, url, maxchildren=max_depth)
            elif context_name:
                scan_id = self.zap.spider.scan(
                    url=url,
                    maxchildren=max_depth,
                    contextname=context_name
                )
            else:
                scan_id = self.zap.spider.scan(url=url, maxchildren=max_depth)

            return scan_id
        except Exception as e:
            print(f"Error starting ZAP spider: {e}")
            return ""

    def wait_for_spider(
        self,
        scan_id: str,
        max_wait: int = 600,
        poll_interval: int = 2
    ) -> bool:
        """
        Wait for spider to complete

        Args:
            scan_id: Spider scan ID
            max_wait: Maximum seconds to wait
            poll_interval: Seconds between status checks

        Returns:
            True if completed, False if timed out
        """
        waited = 0
        while waited < max_wait:
            try:
                status = int(self.zap.spider.status(scan_id))
                if status >= 100:
                    return True
                time.sleep(poll_interval)
                waited += poll_interval
            except Exception as e:
                print(f"Error checking spider status: {e}")
                return False
        return False

    def active_scan(
        self,
        url: str,
        context_name: Optional[str] = None,
        scan_policy: Optional[str] = None,
        user_id: Optional[str] = None,
        context_id: Optional[str] = None
    ) -> str:
        """
        Run ZAP active scan

        Args:
            url: Target URL
            context_name: Optional context to use
            scan_policy: Optional scan policy name

        Returns:
            Active scan ID
        """
        try:
            if user_id is not None and context_id is not None:
                # authenticated active scan — attack as the logged-in user so the
                # app's post-login endpoints (forms, params) are actually exercised
                scan_id = self.zap.ascan.scan_as_user(
                    url, context_id, user_id, recurse=True,
                    scanpolicyname=scan_policy)
            elif context_name:
                scan_id = self.zap.ascan.scan(
                    url=url,
                    contextid=context_name,
                    scanpolicyname=scan_policy
                )
            else:
                scan_id = self.zap.ascan.scan(
                    url=url,
                    scanpolicyname=scan_policy
                )

            return scan_id
        except Exception as e:
            print(f"Error starting ZAP active scan: {e}")
            return ""

    def wait_for_active_scan(
        self,
        scan_id: str,
        max_wait: int = 1800,
        poll_interval: int = 5
    ) -> bool:
        """
        Wait for active scan to complete

        Args:
            scan_id: Active scan ID
            max_wait: Maximum seconds to wait
            poll_interval: Seconds between status checks

        Returns:
            True if completed, False if timed out
        """
        waited = 0
        while waited < max_wait:
            try:
                status = int(self.zap.ascan.status(scan_id))
                if status >= 100:
                    return True
                time.sleep(poll_interval)
                waited += poll_interval
            except Exception as e:
                print(f"Error checking active scan status: {e}")
                return False
        return False

    def get_alerts(
        self,
        base_url: Optional[str] = None,
        start: int = 0,
        count: int = 1000
    ) -> List[Dict]:
        """
        Get ZAP alerts

        Args:
            base_url: Filter by base URL
            start: Starting offset
            count: Maximum number of alerts

        Returns:
            List of alert dictionaries
        """
        try:
            if base_url:
                alerts = self.zap.core.alerts(baseurl=base_url, start=start, count=count)
            else:
                alerts = self.zap.core.alerts(start=start, count=count)

            return alerts
        except Exception as e:
            print(f"Error getting ZAP alerts: {e}")
            return []

    def get_alerts_summary(
        self,
        base_url: Optional[str] = None
    ) -> Dict[str, int]:
        """
        Get summary of alerts by risk level

        Args:
            base_url: Filter by base URL

        Returns:
            Dictionary with counts per risk level
        """
        try:
            alerts = self.get_alerts(base_url=base_url)

            summary = {
                'informational': 0,
                'low': 0,
                'medium': 0,
                'high': 0,
                'total': len(alerts)
            }

            for alert in alerts:
                risk = alert.get('risk', '').lower()
                if risk in summary:
                    summary[risk] += 1

            return summary
        except Exception as e:
            print(f"Error getting alerts summary: {e}")
            return {'total': 0}

    def export_alerts_to_db_format(
        self,
        base_url: str
    ) -> List[Dict]:
        """
        Export ZAP alerts in format suitable for web_findings table

        Args:
            base_url: Base URL of scan

        Returns:
            List of findings in database format
        """
        alerts = self.get_alerts(base_url=base_url)
        findings = []

        severity_map = {
            'Informational': 'info',
            'Low': 'low',
            'Medium': 'medium',
            'High': 'high'
        }

        for alert in alerts:
            finding = {
                'url': alert.get('url', base_url),
                'source': 'zap',
                'issue_type': 'zap-alert',
                'name': alert.get('alert', 'Unknown'),
                'severity': severity_map.get(alert.get('risk', ''), 'info'),
                'evidence': alert.get('evidence', '') or alert.get('attack', '') or alert.get('other', ''),
                'method': alert.get('method', 'GET'),
                'payload': alert.get('attack', ''),
                'cwe': [alert.get('cweid')] if alert.get('cweid') else [],
                'references': {
                    'solution': alert.get('solution', ''),
                    'reference': alert.get('reference', ''),
                    'wascid': alert.get('wascid', ''),
                    'description': alert.get('description', '')
                }
            }
            findings.append(finding)

        return findings

    def cleanup_session(self, context_name: Optional[str] = None):
        """
        Clean up ZAP session

        Args:
            context_name: Optional context to remove
        """
        try:
            if context_name:
                self.zap.context.remove_context(context_name)
        except Exception as e:
            print(f"Error cleaning up ZAP session: {e}")

    def set_scan_policy(
        self,
        policy_name: str,
        attack_strength: str = "DEFAULT",
        alert_threshold: str = "DEFAULT"
    ):
        """
        Configure ZAP scan policy

        Args:
            policy_name: Name for the policy
            attack_strength: LOW, MEDIUM, HIGH, INSANE, or DEFAULT
            alert_threshold: LOW, MEDIUM, HIGH, or DEFAULT
        """
        try:
            # This would require more ZAP API calls to properly configure
            # For now, using default policy
            pass
        except Exception as e:
            print(f"Error setting scan policy: {e}")

    def _active_scan_chunked(self, url: str, context_id=None, user_id=None,
                             chunk_size: int = 10) -> List[Dict]:
        """Active-scan the in-scope URLs in batches, flushing to disk between them.

        For each batch: active-scan the URLs (as the logged-in user when a
        context/user exists), collect their alerts into Python, then
        delete_site_node() the scanned URLs so ZAP's in-memory message store — the
        part that grows to fill the JVM heap during a whole-tree active scan — is
        freed/flushed to the on-disk session DB. Peak ZAP memory stays ~one batch,
        independent of site size. Returns the accumulated alerts (deduped)."""
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        try:
            all_urls = [u for u in (self.zap.core.urls() or [])
                        if urlparse(u).netloc == host]
        except Exception:  # noqa: BLE001
            all_urls = []
        all_urls = list(dict.fromkeys(all_urls)) or [url]
        collected: Dict[tuple, Dict] = {}
        scanned_batch: List[str] = []

        def _flush(batch):
            # collect alerts for the batch, then delete the nodes to free memory
            for bu in batch:
                try:
                    for f in self.export_alerts_to_db_format(bu):
                        collected[(f.get('url'), f.get('name'), f.get('param') or '')] = f
                except Exception:  # noqa: BLE001
                    pass
            for bu in batch:
                try:
                    self.zap.core.delete_site_node(bu)
                except Exception:  # noqa: BLE001
                    pass

        for u in all_urls:
            try:
                if user_id and context_id:
                    sid = self.zap.ascan.scan_as_user(u, context_id, user_id, recurse=False)
                else:
                    sid = self.zap.ascan.scan(url=u, recurse=False)
                if sid and str(sid).isdigit():
                    self.wait_for_active_scan(sid, max_wait=300)
            except Exception as e:  # noqa: BLE001
                print(f"[chunk-ascan] {u}: {e}")
            scanned_batch.append(u)
            if len(scanned_batch) >= max(1, chunk_size):
                _flush(scanned_batch)
                scanned_batch = []
        if scanned_batch:
            _flush(scanned_batch)
        return list(collected.values())

    def configure_ajax_spider_bounds(self, num_browsers=None, max_crawl_states=None,
                                     max_duration_min=None, max_crawl_depth=None) -> Dict:
        """Bound the ajax (browser) spider so it is container-safe. ZAP's default
        here is NumberOfBrowsers=32 with MaxCrawlStates=0 (unlimited) — 32 Firefox
        instances crawling without a state cap balloon memory from ~1GiB to >14GiB
        in seconds and OOM.

        Measured on demo.testfire.net (24GiB container, 300-state cap): 1 browser
        ~+0.4-1GiB, 4 browsers plateaus ~+2.4GiB and stays flat (state cap stops
        runaway), 32 browsers OOMs. Default 4 (fast + safe); env-overridable with
        ZAP_AJAX_BROWSERS / ZAP_AJAX_MAX_STATES / ZAP_AJAX_MAX_DURATION_MIN /
        ZAP_AJAX_MAX_DEPTH so it tunes without a rebuild. Best-effort; returns
        what was set."""
        def _env(name, default):
            try:
                return int(os.environ.get(name, default))
            except Exception:  # noqa: BLE001
                return default
        num_browsers = _env("ZAP_AJAX_BROWSERS", 4) if num_browsers is None else num_browsers
        max_crawl_states = _env("ZAP_AJAX_MAX_STATES", 300) if max_crawl_states is None else max_crawl_states
        max_duration_min = _env("ZAP_AJAX_MAX_DURATION_MIN", 5) if max_duration_min is None else max_duration_min
        max_crawl_depth = _env("ZAP_AJAX_MAX_DEPTH", 5) if max_crawl_depth is None else max_crawl_depth
        out = {}
        opts = {
            "set_option_number_of_browsers": int(num_browsers),
            "set_option_max_crawl_states": int(max_crawl_states),
            "set_option_max_duration": int(max_duration_min),
            "set_option_max_crawl_depth": int(max_crawl_depth),
        }
        for method, val in opts.items():
            try:
                fn = getattr(self.zap.ajaxSpider, method, None)
                if fn:
                    fn(str(val))
                    out[method] = val
            except Exception as e:  # noqa: BLE001
                out[method] = f"err:{str(e)[:60]}"
        return out

    def add_context_user(self, context_id, username, password) -> Optional[str]:
        """Add a SECOND (or Nth) user to an EXISTING context whose authentication
        method is already configured (form or script). Used by the access-control
        (IDOR) scan, which needs two logged-in users to compare who-can-reach-what.
        Returns the new ZAP user id, or None."""
        try:
            import urllib.parse as _up
            if not (username and context_id):
                return None
            uid = self.zap.users.new_user(context_id, username)
            self.zap.users.set_authentication_credentials(
                context_id, uid,
                "username=" + _up.quote(username, safe="")
                + "&password=" + _up.quote(password or "", safe=""))
            self.zap.users.set_user_enabled(context_id, uid, "true")
            print(f"ZAP added access-control user {username} (id {uid}) to context {context_id}")
            return uid
        except Exception as e:  # noqa: BLE001
            print(f"Error adding ZAP context user {username}: {e}")
            return None

    def access_control_scan(self, context_id, user_ids, unauth=True,
                            alert_risk_level="High", max_wait=600) -> Dict:
        """Run the ZAP Access Control Testing add-on (broken access control / IDOR).
        For each URL explored during the (authenticated) crawl+spider, ZAP re-issues
        the request as EACH user (and, when unauth=True, as an unauthenticated user)
        and — using the context's logged-in/out indicators — classifies whether the
        response was authorized. It raises an alert where a user reached a resource
        the access rules say they should not. Needs a context with an auth method and
        at least one enabled user (two users → horizontal-IDOR comparison).

        NOTE on scope: the add-on classifies at the URL/node level. It reliably
        catches FUNCTIONAL/vertical access control (a low-priv user reaching an
        admin URL) and horizontal IDOR where the object reference is in the URL
        PATH or a distinct node. Same-URL, param-VALUE IDOR (e.g.
        showAccount?listAccounts=<other-acct>) is only flagged when the two users'
        crawls recorded DIFFERENT param values as distinct messages — which is why
        the AJAX spider (which exercises dropdowns) must run first. Returns status."""
        out = {"ran": False}
        try:
            uids = [u for u in (user_ids or []) if u]
            if not (context_id and uids):
                out["error"] = "no context/users for access control scan"
                return out
            self.zap.accessControl.scan(
                contextid=str(context_id),
                userid=",".join(str(u) for u in uids),
                scanasunauthuser="true" if unauth else "false",
                raisealert="true",
                alertrisklevel=alert_risk_level,
            )
            out["ran"] = True
            # getScanStatus returns a numeric percentage WHILE running and the
            # literal "NOT RUNNING" when idle/finished (NOT "100"). Give it a moment
            # to spin up, then treat "NOT RUNNING"/100 as done — otherwise the poll
            # spins the full max_wait after the scan has already completed.
            time.sleep(3)
            waited = 3
            while waited < max_wait:
                try:
                    st = self.zap.accessControl.get_scan_status(contextid=str(context_id))
                except Exception:
                    st = None
                out["status"] = str(st)
                s = str(st).strip().upper()
                if s in ("NOT RUNNING", "100", "COMPLETED", "FINISHED"):
                    out["completed"] = True
                    break
                time.sleep(5)
                waited += 5
            out.setdefault("completed", False)
        except Exception as e:  # noqa: BLE001
            out["error"] = str(e)[:200]
        return out

    async def scan_with_playwright_session(
        self,
        url: str,
        do_spider: bool = True,
        do_active_scan: bool = True,
        context_name: Optional[str] = None,
        auth: Optional[Dict] = None,
        do_ajax_spider: bool = False,
        active_scan_chunk_size: int = 0,
        second_auth: Optional[Dict] = None,
        do_access_control: bool = False,
    ) -> Dict:
        """
        Full ZAP scan after Playwright has explored the site

        Args:
            url: Target URL
            do_spider: Run spider
            do_active_scan: Run active scan
            context_name: Optional context name

        Returns:
            Dictionary with scan results
        """
        results = {
            'spider_id': None,
            'spider_completed': False,
            'active_scan_id': None,
            'active_scan_completed': False,
            'alerts': [],
            'alerts_summary': {}
        }

        if not self.is_zap_ready():
            results['error'] = 'ZAP not ready'
            return results

        # AUTHENTICATED scan: when auth config is supplied, build a context and a
        # forced logged-in user so the spider + active scan run authenticated —
        # this is what pulls vulns out of login-gated apps (any app, not just one).
        user_id = None
        context_id = None
        access_user_ids = []
        if auth and auth.get("login_url"):
            context_name = context_name or f"authctx_{int(time.time())}"
            context_id = self.create_context(context_name, url)
            user_id = self.configure_authentication(context_name, context_id, auth)
            if user_id:
                access_user_ids.append(user_id)
                # Second user for the horizontal-IDOR (access-control) comparison.
                # The context's auth method is already set; just add creds+enable.
                if second_auth and second_auth.get("username"):
                    uid2 = self.add_context_user(
                        context_id, second_auth.get("username"), second_auth.get("password"))
                    if uid2:
                        self.zap.users.set_user_enabled(context_id, uid2, "true")
                        access_user_ids.append(uid2)
                        results['access_control_users'] = len(access_user_ids)
            if not user_id:
                results['authenticated'] = False
                results['auth_error'] = 'authentication config incomplete or ZAP rejected it'
            else:
                # VERIFY the login actually worked rather than assuming
                # authenticated == user-created (a user object is not a session).
                verified = self.verify_authentication(context_id, user_id)
                results['auth_verified'] = verified
                results['authenticated'] = bool(verified) if verified is not None else bool(user_id)
                if verified is False:
                    results['auth_error'] = ('ZAP did not confirm a login — check '
                                             'login_url/login_data and the indicators')

        # TOKEN/HEADER auth (bearer/JWT/API-key): inject the Auth Profile's session
        # headers into every request. Independent of a login form, so a token-only
        # profile (no login_url) still scans authenticated.
        _sess_headers = (auth or {}).get("session", {}).get("headers") if auth else None
        if _sess_headers:
            results['session_headers_injected'] = self.apply_session_headers(_sess_headers)
            results['authenticated'] = True

        # Only reference the ZAP context if one was actually created (auth path).
        # Passing a context_name that was never created makes spider.scan/ascan
        # return "does_not_exist" instead of a scan id.
        _ctx_name = context_name if context_id else None

        # OPTIONAL ajax spider — OFF by default. It drives real browsers (memory-
        # heavy and slow) and is redundant when an authenticated Playwright crawl
        # has already seeded the tree; enable it only for a JS-heavy SPA that the
        # traditional spider can't map. Best-effort, bounded.
        if do_ajax_spider:
            try:
                # BOUND the ajax spider first — the default 32 browsers /
                # unlimited crawl states OOMs the container (measured: 1GiB->14GiB
                # in seconds). 1 browser + a state cap keeps memory flat.
                results['ajax_spider_bounds'] = self.configure_ajax_spider_bounds()
                # NOTE: ajaxSpider.scan_as_user takes (contextname, USERNAME, ...) —
                # the username STRING, not the numeric user id (unlike spider.scan_as_user
                # which takes contextid+userid). Passing the id makes ZAP fail to find
                # the user and the ajax crawl silently returns 0 results.
                _ajax_user = (auth or {}).get("username") if auth else None
                if _ajax_user and context_id:
                    self.zap.ajaxSpider.scan_as_user(_ctx_name, _ajax_user, url, subtreeonly=None)
                else:
                    self.zap.ajaxSpider.scan(url, inscope=None, contextname=_ctx_name, subtreeonly=None)
                waited = 0
                while str(self.zap.ajaxSpider.status).lower() == "running" and waited < 300:
                    time.sleep(3)
                    waited += 3
                results['ajax_spider'] = {"ran": True, "status": str(self.zap.ajaxSpider.status)}
            except Exception as e:  # noqa: BLE001
                results['ajax_spider'] = {"ran": False, "error": str(e)[:160]}

        if do_spider:
            results['spider_id'] = self.spider_url(
                url, context_name=_ctx_name, user_id=user_id, context_id=context_id)
            if results['spider_id']:
                results['spider_completed'] = self.wait_for_spider(results['spider_id'])

        # ACCESS CONTROL (broken access control / IDOR) — run AFTER the crawl+spider
        # have populated the context's message tree, but BEFORE the active scan
        # (the CHUNKED active scan deletes site-tree nodes to flush memory, which
        # would leave access control nothing to re-request). Its alerts land in the
        # same store and are picked up by the export below. Needs a context with an
        # auth method + >=1 user; a second user enables the horizontal-IDOR compare.
        if do_access_control and context_id and access_user_ids:
            results['access_control'] = self.access_control_scan(
                context_id, access_user_ids, unauth=True)

        _chunk_alerts = None
        if do_active_scan:
            if active_scan_chunk_size and active_scan_chunk_size > 0:
                # CHUNKED active scan: scan the in-scope URLs in batches, collect
                # each batch's alerts into Python, then delete the scanned nodes
                # from ZAP so its in-memory message store (the thing that grows to
                # fill the heap) is flushed to disk/freed between batches. Keeps
                # ZAP's peak memory ~one batch, independent of site size.
                results['active_scan_chunked'] = True
                _chunk_alerts = self._active_scan_chunked(
                    url, context_id=context_id, user_id=user_id,
                    chunk_size=active_scan_chunk_size)
                results['active_scan_completed'] = True
            else:
                results['active_scan_id'] = self.active_scan(
                    url, context_name=_ctx_name, user_id=user_id, context_id=context_id)
                if results['active_scan_id']:
                    results['active_scan_completed'] = self.wait_for_active_scan(
                        results['active_scan_id'],
                        max_wait=900  # 15 minutes max for active scan
                    )

        results['alerts'] = (_chunk_alerts if _chunk_alerts is not None
                             else self.export_alerts_to_db_format(url))
        results['alerts_summary'] = self.get_alerts_summary(url)

        return results
