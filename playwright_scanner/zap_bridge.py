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

    def spider_url(
        self,
        url: str,
        context_name: Optional[str] = None,
        max_depth: int = 5,
        max_duration: int = 300
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
            if context_name:
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
        scan_policy: Optional[str] = None
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
            if context_name:
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

    async def scan_with_playwright_session(
        self,
        url: str,
        do_spider: bool = True,
        do_active_scan: bool = True,
        context_name: Optional[str] = None
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

        if do_spider:
            results['spider_id'] = self.spider_url(url, context_name=context_name)
            if results['spider_id']:
                results['spider_completed'] = self.wait_for_spider(results['spider_id'])

        if do_active_scan:
            results['active_scan_id'] = self.active_scan(url, context_name=context_name)
            if results['active_scan_id']:
                results['active_scan_completed'] = self.wait_for_active_scan(
                    results['active_scan_id'],
                    max_wait=900  # 15 minutes max for active scan
                )

        results['alerts'] = self.export_alerts_to_db_format(url)
        results['alerts_summary'] = self.get_alerts_summary(url)

        return results
