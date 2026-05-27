"""
Web Scan Pipeline Orchestrator
Sequential web scan pipeline with data sharing between stages:
wafw00f → Katana → Playwright crawl → Gobuster → Nikto → Nuclei → ZAP → GoWitness → Playwright full scan

All discovery tools run first so their URLs seed into ZAP (the final
comprehensive aggregation scanner).  After ZAP completes its XML report
is saved to the scan session directory for export.  GoWitness screenshots
and Playwright full scan (DOM analysis, content extraction, version detection)
run last.
"""

import os
import logging
import pathlib
import httpx
import psycopg2
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger("web_scanner.pipeline")

# Service URLs from environment
PLAYWRIGHT_URL = os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014")
NUCLEI_URL = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"
PD_RUNNER_URL = os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023")
OSINT_RUNNER_URL = os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024")
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
REPORT_DIR = pathlib.Path(os.environ.get("REPORT_DIR", "/reports"))
ZAP_ADDR = os.environ.get("ZAP_ADDR", "zap")
ZAP_PORT = int(os.environ.get("ZAP_PORT", "8090"))
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "changeme")


def _db_conn():
    return psycopg2.connect(DB_DSN)


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {
            "event_type": event_type,
            "source": source,
            "data": data
        }
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload,
            timeout=5,
            verify=False
        )
    except Exception as e:
        logger.warning(f"Failed to emit webhook: {e}")


class WebScanPipeline:
    """
    Sequential web scan pipeline with data sharing between stages.

    Pipeline order:
    1. Katana - JS-aware crawling for endpoints, forms, JS URLs
    2. Playwright - Browser-based scanning of discovered paths
    3. Gobuster - Directory/file brute force discovery
    4. Nikto - Web server security scanning (URIs feed ZAP)
    5. Nuclei - CVE and misconfiguration detection
    6. ZAP - Final comprehensive scan seeded with ALL discovered URLs,
             exports XML report

    All discovery tools (1-4) run first so their URLs seed into ZAP.
    """

    def __init__(self, job_tracker, gobuster_func, zap_func, nikto_func=None):
        """
        Initialize pipeline with required dependencies.

        Args:
            job_tracker: JobTracker instance for progress updates
            gobuster_func: Function to run Gobuster scans
            zap_func: Function to run ZAP scans
            nikto_func: Function to run Nikto scans (optional)
        """
        self.job_tracker = job_tracker
        self.gobuster_func = gobuster_func
        self.zap_func = zap_func
        self.nikto_func = nikto_func
        self.client = httpx.Client(verify=False, timeout=300.0)

    def run_pipeline(
        self,
        target_url: str,
        job_id: str,
        wordlist: Optional[str] = None,
        max_paths_to_visit: int = 50,
        skip_gobuster: bool = False,
        skip_playwright: bool = False,
        skip_zap: bool = False,
        skip_nuclei: bool = False,
        skip_nikto: bool = False,
        skip_katana: bool = False,
        skip_wafw00f: bool = False
    ) -> Dict[str, Any]:
        """
        Run full sequential pipeline: wafw00f → Katana → Playwright → Gobuster → Nikto → Nuclei → ZAP

        WAF detection runs first to inform the tester. All discovery tools
        run before ZAP so their URLs seed into ZAP (the final comprehensive
        aggregation scanner). ZAP exports an XML report at the end.

        Args:
            target_url: Target URL (e.g., "http://192.168.1.150")
            job_id: Job ID for progress tracking
            wordlist: Wordlist for Gobuster (default: medium)
            max_paths_to_visit: Max paths to visit with Playwright
            skip_gobuster: Skip Gobuster stage
            skip_playwright: Skip Playwright stage
            skip_zap: Skip ZAP stage
            skip_nuclei: Skip Nuclei stage
            skip_nikto: Skip Nikto stage
            skip_katana: Skip Katana stage
            skip_wafw00f: Skip wafw00f WAF detection stage

        Returns:
            Dictionary with results from all stages
        """
        context = {
            "target": target_url,
            "job_id": job_id,
            "started_at": datetime.now().isoformat(),
            "paths": [],
            "urls": [],
            "stages": {},
            "errors": [],
            "waf_detected": None,
        }

        try:
            # Stage 0: wafw00f — WAF detection (runs first to inform tester)
            if not skip_wafw00f:
                self._update_stage(job_id, "wafw00f", "running")
                logger.info(f"[{job_id[:8]}] Stage 0: Running wafw00f on {target_url}")
                emit_webhook_event("stage_started", "wafw00f", {
                    "job_id": job_id, "stage": "wafw00f", "target": target_url,
                })
                try:
                    waf_result = self._run_wafw00f(target_url, job_id)
                    context["stages"]["wafw00f"] = waf_result
                    context["waf_detected"] = waf_result.get("firewall")
                    if waf_result.get("firewall"):
                        logger.info(f"[{job_id[:8]}] WAF detected: {waf_result['firewall']}")
                    else:
                        logger.info(f"[{job_id[:8]}] No WAF detected")
                    emit_webhook_event("stage_completed", "wafw00f", {
                        "job_id": job_id, "stage": "wafw00f",
                        "firewall": waf_result.get("firewall"),
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] wafw00f failed: {e}")
                    context["stages"]["wafw00f"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"wafw00f: {e}")
            else:
                context["stages"]["wafw00f"] = {"status": "skipped"}

            # Stage 1: Katana - JS-aware Web Crawling (discovers URLs first)
            if not skip_katana:
                self._update_stage(job_id, "katana", "running")
                logger.info(f"[{job_id[:8]}] Stage 1: Running Katana on {target_url}")

                emit_webhook_event("stage_started", "katana", {
                    "job_id": job_id,
                    "stage": "katana",
                    "target": target_url,
                    "urls_count": len(context["urls"])
                })

                try:
                    katana_result = self._run_katana(target_url, context["urls"])
                    context["stages"]["katana"] = {
                        "status": "completed",
                        "urls_found": katana_result.get("urls_found", 0),
                    }
                    # Merge discovered URLs
                    if katana_result.get("discovered_urls"):
                        context["urls"].extend(katana_result["discovered_urls"])
                        context["urls"] = list(set(context["urls"]))  # Dedupe
                    logger.info(f"[{job_id[:8]}] Katana discovered {katana_result.get('urls_found', 0)} URLs (total now: {len(context['urls'])})")

                    emit_webhook_event("stage_completed", "katana", {
                        "job_id": job_id,
                        "stage": "katana",
                        "target": target_url,
                        "urls_found": katana_result.get("urls_found", 0),
                        "total_urls": len(context["urls"])
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] Katana failed: {e}")
                    context["stages"]["katana"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"Katana: {e}")

                    emit_webhook_event("stage_failed", "katana", {
                        "job_id": job_id,
                        "stage": "katana",
                        "target": target_url,
                        "error": str(e)
                    })

                self._update_stage(job_id, "katana", "done")
            else:
                context["stages"]["katana"] = {"status": "skipped"}

            # Stage 2: Playwright - Browser Crawl (feeds ZAP via proxy)
            if not skip_playwright:
                self._update_stage(job_id, "playwright", "running")
                logger.info(f"[{job_id[:8]}] Stage 2: Playwright crawl on {target_url} (seeding {len(context['urls'])} URLs from Katana)")

                emit_webhook_event("stage_started", "playwright", {
                    "job_id": job_id,
                    "stage": "playwright",
                    "target": target_url,
                    "seed_urls": len(context["urls"])
                })

                try:
                    playwright_result = self._run_playwright_crawl(
                        target_url, context["urls"], max_pages=max_paths_to_visit
                    )
                    context["stages"]["playwright"] = {
                        "status": "completed",
                        "pages_crawled": playwright_result.get("pages_visited", 0),
                        "urls_discovered": playwright_result.get("urls_discovered", 0),
                        "crawl_job_id": playwright_result.get("job_id"),
                    }
                    # Merge discovered URLs into pipeline context
                    if playwright_result.get("discovered_urls"):
                        context["urls"].extend(playwright_result["discovered_urls"])
                        context["urls"] = list(set(context["urls"]))  # Dedupe
                    logger.info(
                        f"[{job_id[:8]}] Playwright crawled {playwright_result.get('pages_visited', 0)} pages, "
                        f"discovered {playwright_result.get('urls_discovered', 0)} URLs "
                        f"(total now: {len(context['urls'])}). All traffic fed to ZAP via proxy."
                    )

                    emit_webhook_event("stage_completed", "playwright", {
                        "job_id": job_id,
                        "stage": "playwright",
                        "target": target_url,
                        "pages_crawled": playwright_result.get("pages_visited", 0),
                        "urls_discovered": playwright_result.get("urls_discovered", 0),
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] Playwright crawl failed: {e}")
                    context["stages"]["playwright"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"Playwright: {e}")

                    emit_webhook_event("stage_failed", "playwright", {
                        "job_id": job_id,
                        "stage": "playwright",
                        "target": target_url,
                        "error": str(e)
                    })

                self._update_stage(job_id, "playwright", "done")
            else:
                context["stages"]["playwright"] = {"status": "skipped"}

            # Stage 3: Gobuster - Directory Discovery
            if not skip_gobuster:
                self._update_stage(job_id, "gobuster", "running")
                logger.info(f"[{job_id[:8]}] Stage 3: Running Gobuster on {target_url}")

                emit_webhook_event("stage_started", "gobuster", {
                    "job_id": job_id,
                    "stage": "gobuster",
                    "target": target_url,
                    "wordlist": wordlist
                })

                try:
                    gobuster_result = self._run_gobuster(target_url, wordlist)
                    context["paths"] = gobuster_result.get("paths", [])
                    context["stages"]["gobuster"] = {
                        "status": "completed",
                        "paths_found": len(context["paths"]),
                        "findings_saved": gobuster_result.get("findings_saved", 0)
                    }
                    logger.info(f"[{job_id[:8]}] Gobuster found {len(context['paths'])} paths")

                    # Build URLs from Gobuster paths and merge into context
                    gobuster_urls = self._build_urls(target_url, context["paths"], max_paths_to_visit)
                    context["urls"].extend(gobuster_urls)
                    context["urls"] = list(set(context["urls"]))  # Dedupe
                    logger.info(f"[{job_id[:8]}] Total URLs after Gobuster: {len(context['urls'])}")

                    emit_webhook_event("stage_completed", "gobuster", {
                        "job_id": job_id,
                        "stage": "gobuster",
                        "target": target_url,
                        "paths_found": len(context["paths"]),
                        "findings_saved": gobuster_result.get("findings_saved", 0)
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] Gobuster failed: {e}")
                    context["stages"]["gobuster"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"Gobuster: {e}")

                    emit_webhook_event("stage_failed", "gobuster", {
                        "job_id": job_id,
                        "stage": "gobuster",
                        "target": target_url,
                        "error": str(e)
                    })

                self._update_stage(job_id, "gobuster", "done")
            else:
                context["stages"]["gobuster"] = {"status": "skipped"}

            # Stage 4: Nikto - Web Server Security Scanner
            if not skip_nikto:
                self._update_stage(job_id, "nikto", "running")
                logger.info(f"[{job_id[:8]}] Stage 4: Running Nikto on {target_url}")

                emit_webhook_event("stage_started", "nikto", {
                    "job_id": job_id,
                    "stage": "nikto",
                    "target": target_url,
                })

                try:
                    nikto_result = self._run_nikto(target_url)
                    context["stages"]["nikto"] = {
                        "status": "completed",
                        "findings_count": nikto_result.get("findings_count", 0),
                        "output_file": nikto_result.get("output_file"),
                    }
                    logger.info(f"[{job_id[:8]}] Nikto found {nikto_result.get('findings_count', 0)} findings")

                    # Extract URIs from nikto findings in DB and merge into URL list for ZAP
                    nikto_urls = self._extract_nikto_urls(target_url)
                    if nikto_urls:
                        before = len(context["urls"])
                        context["urls"].extend(nikto_urls)
                        context["urls"] = list(set(context["urls"]))  # Dedupe
                        logger.info(f"[{job_id[:8]}] Nikto contributed {len(context['urls']) - before} new URLs (total: {len(context['urls'])})")

                    emit_webhook_event("stage_completed", "nikto", {
                        "job_id": job_id,
                        "stage": "nikto",
                        "target": target_url,
                        "findings_count": nikto_result.get("findings_count", 0),
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] Nikto failed: {e}")
                    context["stages"]["nikto"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"Nikto: {e}")

                    emit_webhook_event("stage_failed", "nikto", {
                        "job_id": job_id,
                        "stage": "nikto",
                        "target": target_url,
                        "error": str(e),
                    })

                self._update_stage(job_id, "nikto", "done")
            else:
                context["stages"]["nikto"] = {"status": "skipped"}

            # Stage 5: Nuclei - CVE and Misconfiguration Detection
            if not skip_nuclei:
                self._update_stage(job_id, "nuclei", "running")
                logger.info(f"[{job_id[:8]}] Stage 5: Running Nuclei on {len(context['urls'])} URLs")

                emit_webhook_event("stage_started", "nuclei", {
                    "job_id": job_id,
                    "stage": "nuclei",
                    "target": target_url,
                    "urls_count": len(context["urls"])
                })

                try:
                    nuclei_result = self._run_nuclei(target_url, context["paths"])
                    context["stages"]["nuclei"] = {
                        "status": "completed",
                        "findings_count": nuclei_result.get("findings_count", 0),
                        "job_id": nuclei_result.get("job_id")
                    }
                    logger.info(f"[{job_id[:8]}] Nuclei found {nuclei_result.get('findings_count', 0)} vulnerabilities")

                    emit_webhook_event("stage_completed", "nuclei", {
                        "job_id": job_id,
                        "stage": "nuclei",
                        "target": target_url,
                        "findings_count": nuclei_result.get("findings_count", 0),
                        "nuclei_job_id": nuclei_result.get("job_id")
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] Nuclei failed: {e}")
                    context["stages"]["nuclei"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"Nuclei: {e}")

                    emit_webhook_event("stage_failed", "nuclei", {
                        "job_id": job_id,
                        "stage": "nuclei",
                        "target": target_url,
                        "error": str(e)
                    })

                self._update_stage(job_id, "nuclei", "done")
            else:
                context["stages"]["nuclei"] = {"status": "skipped"}

            # Stage 6: ZAP - Final comprehensive scan seeded with ALL discovered URLs
            if not skip_zap:
                self._update_stage(job_id, "zap", "running")
                logger.info(f"[{job_id[:8]}] Stage 6: Running ZAP with {len(context['urls'])} seeded URLs (final stage)")

                emit_webhook_event("stage_started", "zap", {
                    "job_id": job_id,
                    "stage": "zap",
                    "target": target_url,
                    "urls_seeded": len(context["urls"])
                })

                try:
                    zap_result = self._run_zap(target_url, context["urls"], job_id)
                    context["stages"]["zap"] = {
                        "status": "completed",
                        "alerts_found": zap_result.get("alerts_found", 0),
                        "alerts": zap_result.get("alerts", []),
                        "urls_seeded": len(context["urls"]),
                        "xml_report": zap_result.get("xml_report")
                    }
                    logger.info(f"[{job_id[:8]}] ZAP found {zap_result.get('alerts_found', 0)} alerts")

                    emit_webhook_event("stage_completed", "zap", {
                        "job_id": job_id,
                        "stage": "zap",
                        "target": target_url,
                        "alerts_found": zap_result.get("alerts_found", 0),
                        "urls_seeded": len(context["urls"])
                    })
                except Exception as e:
                    logger.error(f"[{job_id[:8]}] ZAP failed: {e}")
                    context["stages"]["zap"] = {"status": "failed", "error": str(e)}
                    context["errors"].append(f"ZAP: {e}")

                    emit_webhook_event("stage_failed", "zap", {
                        "job_id": job_id,
                        "stage": "zap",
                        "target": target_url,
                        "error": str(e)
                    })

                self._update_stage(job_id, "zap", "done")
            else:
                context["stages"]["zap"] = {"status": "skipped"}

            # Stage 7: GoWitness screenshots
            self._update_stage(job_id, "gowitness", "running")
            logger.info(f"[{job_id[:8]}] Stage 7: GoWitness screenshots on {target_url}")
            try:
                gw_targets = list(dict.fromkeys([target_url] + context["urls"][:99]))
                gw_payload = {"targets": gw_targets, "timeout": 10, "resolution": "1440x900"}
                gw_resp = self.client.post(
                    f"{OSINT_RUNNER_URL}/jobs/gowitness",
                    json=gw_payload,
                    headers={"x-api-key": API_KEY},
                    timeout=30,
                )
                if gw_resp.status_code == 200:
                    import time as _gw_time
                    gw_job_id = gw_resp.json().get("job_id")
                    if gw_job_id:
                        deadline = _gw_time.time() + 300  # 5 min max
                        while _gw_time.time() < deadline:
                            gr = self.client.get(
                                f"{OSINT_RUNNER_URL}/jobs/{gw_job_id}",
                                headers={"x-api-key": API_KEY}, timeout=10,
                            )
                            if gr.status_code == 200:
                                gd = gr.json()
                                if gd.get("status") in ("completed", "failed"):
                                    gw_result = gd.get("result", {})
                                    context["stages"]["gowitness"] = {
                                        "status": "completed",
                                        "screenshots": gw_result.get("screenshots", 0),
                                    }
                                    logger.info(f"[{job_id[:8]}] GoWitness captured {gw_result.get('screenshots', 0)} screenshots")
                                    break
                            _gw_time.sleep(3)
                        else:
                            context["stages"]["gowitness"] = {"status": "timeout"}
                            logger.warning(f"[{job_id[:8]}] GoWitness timed out")
                else:
                    context["stages"]["gowitness"] = {"status": "failed", "error": f"HTTP {gw_resp.status_code}"}
                    logger.warning(f"[{job_id[:8]}] GoWitness returned {gw_resp.status_code}")
            except Exception as e:
                logger.error(f"[{job_id[:8]}] GoWitness failed: {e}")
                context["stages"]["gowitness"] = {"status": "failed", "error": str(e)}
                context["errors"].append(f"GoWitness: {e}")
            self._update_stage(job_id, "gowitness", "done")

            # Stage 8: Playwright full scan (DOM analysis, content extraction, security headers, JS libs, screenshot)
            self._update_stage(job_id, "playwright_scan", "running")
            logger.info(f"[{job_id[:8]}] Stage 8: Playwright full scan (DOM analysis + version detection)")
            try:
                pw_scan_resp = self.client.post(
                    f"{PLAYWRIGHT_URL}/scan",
                    json={
                        "url": target_url,
                        "capture_screenshots": True,
                        "capture_dom": True,
                        "run_security_checks": True,
                        "use_zap_proxy": False,
                        "zap_spider": False,
                        "zap_active_scan": False,
                    },
                    timeout=30.0,
                )
                if pw_scan_resp.status_code == 200:
                    import time as _pw_time
                    pw_data = pw_scan_resp.json()
                    pw_scan_job_id = pw_data.get("scan_id")
                    if pw_scan_job_id:
                        deadline = _pw_time.time() + 600  # 10 min max
                        while _pw_time.time() < deadline:
                            sr = self.client.get(
                                f"{PLAYWRIGHT_URL}/scan/{pw_scan_job_id}",
                                timeout=10.0,
                            )
                            if sr.status_code == 200:
                                sd = sr.json()
                                if sd.get("status") in ("completed", "failed"):
                                    context["stages"]["playwright_scan"] = {
                                        "status": sd.get("status"),
                                        "pages_scanned": sd.get("pages_scanned", 0),
                                        "findings": sd.get("findings_count", 0),
                                    }
                                    logger.info(f"[{job_id[:8]}] Playwright full scan: {sd.get('pages_scanned', 0)} pages, {sd.get('findings_count', 0)} findings")
                                    break
                            _pw_time.sleep(5)
                        else:
                            context["stages"]["playwright_scan"] = {"status": "timeout"}
                            logger.warning(f"[{job_id[:8]}] Playwright full scan timed out")
                    else:
                        context["stages"]["playwright_scan"] = {"status": "completed", "note": "inline"}
                else:
                    context["stages"]["playwright_scan"] = {"status": "failed", "error": f"HTTP {pw_scan_resp.status_code}"}
                    logger.warning(f"[{job_id[:8]}] Playwright full scan returned {pw_scan_resp.status_code}")
            except Exception as e:
                logger.error(f"[{job_id[:8]}] Playwright full scan failed: {e}")
                context["stages"]["playwright_scan"] = {"status": "failed", "error": str(e)}
                context["errors"].append(f"Playwright scan: {e}")
            self._update_stage(job_id, "playwright_scan", "done")

            context["completed_at"] = datetime.now().isoformat()
            context["status"] = "completed" if not context["errors"] else "completed_with_errors"

        except Exception as e:
            logger.error(f"[{job_id[:8]}] Pipeline failed: {e}")
            context["error"] = str(e)
            context["status"] = "failed"
            context["completed_at"] = datetime.now().isoformat()

        return context

    def _update_stage(self, job_id: str, stage: str, status: str):
        """Update job tracker with current stage"""
        self.job_tracker.update_progress(job_id, stage=f"{stage}_{status}")

    def _build_urls(self, base_url: str, paths: List[Dict], max_count: int) -> List[str]:
        """Build list of URLs from base URL and discovered paths"""
        urls = [base_url]
        for path_info in paths[:max_count]:
            path = path_info.get("path", "") if isinstance(path_info, dict) else path_info
            if path and not path.startswith("http"):
                # Ensure path starts with /
                if not path.startswith("/"):
                    path = "/" + path
                urls.append(f"{base_url.rstrip('/')}{path}")
        return urls

    def _run_gobuster(self, url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Run Gobuster and return discovered paths.

        Returns:
            Dict with 'paths' list and 'findings_saved' count
        """
        from web_scan import gobuster_dir_with_paths
        return gobuster_dir_with_paths(url, wordlist=wordlist)

    def _run_playwright_crawl(
        self, base_url: str, seed_urls: List[str], max_pages: int = 50
    ) -> Dict[str, Any]:
        """
        Run Playwright browser crawl that follows links and feeds ZAP via proxy.

        The crawl visits pages using a real browser, follows links up to max_depth,
        and routes ALL traffic through ZAP's proxy. This means ZAP automatically
        builds its site tree from every request Playwright makes — giving ZAP
        much better coverage than just seeding URLs.

        Args:
            base_url: Starting URL for the crawl
            seed_urls: Additional URLs discovered by earlier stages (e.g. Katana)
            max_pages: Maximum number of pages to crawl

        Returns:
            Dict with 'pages_visited', 'urls_discovered', 'discovered_urls', 'job_id'
        """
        import time as _time

        result = {
            "pages_visited": 0,
            "urls_discovered": 0,
            "discovered_urls": [],
            "job_id": None,
        }

        try:
            # Start the crawl via Playwright's /crawl endpoint
            response = self.client.post(
                f"{PLAYWRIGHT_URL}/crawl",
                json={
                    "url": base_url,
                    "max_depth": 3,
                    "max_pages": max_pages,
                    "seed_urls": seed_urls[:200],  # Cap seeds to avoid huge payloads
                    "use_zap_proxy": True,
                    "same_origin_only": True,
                },
                timeout=30.0,
            )

            if response.status_code != 200:
                logger.warning(f"Playwright crawl start failed: HTTP {response.status_code}")
                return result

            data = response.json()
            crawl_job_id = data.get("job_id")
            result["job_id"] = crawl_job_id
            logger.info(f"Playwright crawl started: job_id={crawl_job_id}")

            if not crawl_job_id:
                return result

            # Poll for completion (max 10 minutes)
            deadline = _time.time() + 600
            while _time.time() < deadline:
                try:
                    status_resp = self.client.get(
                        f"{PLAYWRIGHT_URL}/crawl/{crawl_job_id}",
                        timeout=10.0,
                    )
                    if status_resp.status_code == 200:
                        status_data = status_resp.json()
                        status = status_data.get("status")

                        if status in ("completed", "failed"):
                            result["pages_visited"] = status_data.get("pages_visited", 0)
                            result["urls_discovered"] = status_data.get("urls_discovered", 0)
                            result["discovered_urls"] = status_data.get("discovered_urls", [])
                            return result
                except Exception as e:
                    logger.warning(f"Error polling Playwright crawl status: {e}")

                _time.sleep(5)

            logger.warning(f"Playwright crawl timed out for {base_url}")
            return result

        except Exception as e:
            logger.warning(f"Playwright crawl error: {e}")
            return result

    def _run_zap(self, base_url: str, discovered_urls: List[str], job_id: str = "") -> Dict[str, Any]:
        """
        Run ZAP scan with pre-seeded URLs and export XML report.

        Args:
            base_url: Base URL for the scan
            discovered_urls: All URLs discovered by previous pipeline stages
            job_id: Pipeline job ID (used in XML filename)

        Returns:
            Dict with 'alerts_found' count, 'alerts' list, and 'xml_report' path
        """
        from web_scan import zap_scan_with_urls
        zap_result = zap_scan_with_urls(base_url, discovered_urls=discovered_urls)

        result = {
            "alerts_found": zap_result["count"],
            "alerts": zap_result["alerts"],
        }

        # Export ZAP XML report after scan completes
        try:
            from zapv2 import ZAPv2
            proxies = {
                "http": f"http://{ZAP_ADDR}:{ZAP_PORT}",
                "https": f"http://{ZAP_ADDR}:{ZAP_PORT}",
            }
            zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)
            xml_report = zap.core.xmlreport()
            jid8 = job_id[:8] if job_id else "unknown"
            xml_path = str(REPORT_DIR / f"zap_report_{jid8}.xml")
            with open(xml_path, "w") as f:
                f.write(xml_report)
            result["xml_report"] = xml_path
            logger.info(f"[ZAP] XML report saved to {xml_path}")
        except Exception as e:
            logger.warning(f"[ZAP] Failed to export XML report: {e}")

        return result

    def _run_nuclei(self, base_url: str, paths: List[Dict]) -> Dict[str, Any]:
        """
        Run Nuclei scan on target with discovered paths.

        Args:
            base_url: Base URL of the target
            paths: List of path dicts from Gobuster

        Returns:
            Dict with scan results
        """
        result = {
            "findings_count": 0,
            "job_id": None
        }

        # Build list of URLs for Nuclei
        urls = [base_url]
        for path_info in paths[:100]:  # Limit paths for Nuclei
            path = path_info.get("path", "") if isinstance(path_info, dict) else path_info
            if path:
                if not path.startswith("/"):
                    path = "/" + path
                urls.append(f"{base_url.rstrip('/')}{path}")

        try:
            # Start Nuclei scan via API
            response = self.client.post(
                f"{NUCLEI_URL}/jobs/nuclei-scan",
                json={
                    "target_urls": urls,
                    "severity": "low,medium,high,critical",
                    "limit": len(urls)
                },
                timeout=30.0
            )

            if response.status_code == 200:
                data = response.json()
                result["job_id"] = data.get("job_id")
                logger.info(f"Nuclei scan started: job_id={result['job_id']}")

                # Wait for Nuclei to complete (with timeout)
                if result["job_id"]:
                    nuclei_result = self._wait_for_nuclei(result["job_id"])
                    result["findings_count"] = nuclei_result.get("findings_count", 0)
            else:
                logger.warning(f"Nuclei scan start failed: HTTP {response.status_code}")

        except Exception as e:
            logger.warning(f"Nuclei scan error: {e}")

        return result

    def _run_nikto(self, url: str) -> Dict[str, Any]:
        """
        Run Nikto web server scanner on target.

        Args:
            url: Target URL

        Returns:
            Dict with 'findings_count' and optional 'output_file'
        """
        if self.nikto_func:
            result = self.nikto_func(url)
        else:
            from web_scan import nikto_scan
            result = nikto_scan(url)

        if isinstance(result, dict):
            return {"findings_count": result.get("count", 0), "output_file": result.get("output_file")}
        return {"findings_count": result}

    def _extract_nikto_urls(self, target_url: str) -> List[str]:
        """
        Query web_findings for nikto source entries matching the target URL
        and return the discovered URLs to seed into ZAP.
        """
        urls = []
        try:
            with _db_conn() as c, c.cursor() as cur:
                cur.execute(
                    "SELECT DISTINCT url FROM web_findings WHERE source = 'nikto' AND url LIKE %s",
                    (f"{target_url.rstrip('/')}%",)
                )
                urls = [row[0] for row in cur.fetchall() if row[0]]
            logger.info(f"[nikto] Extracted {len(urls)} URLs from nikto findings for ZAP seeding")
        except Exception as e:
            logger.warning(f"[nikto] Failed to extract URLs from DB: {e}")
        return urls

    def _run_wafw00f(self, target_url: str, job_id: str) -> Dict[str, Any]:
        """
        Run wafw00f WAF detection via osint-runner.

        Args:
            target_url: Target URL
            job_id: Job ID for tracking

        Returns:
            Dict with firewall name (or None), status, and raw output
        """
        import time as _time
        try:
            resp = requests.post(
                f"{OSINT_RUNNER_URL}/jobs/wafw00f",
                json={"targets": [target_url]},
                headers={"x-api-key": API_KEY},
                timeout=30,
                verify=False
            )
            if resp.status_code != 200:
                return {"status": "failed", "error": f"HTTP {resp.status_code}", "firewall": None}

            waf_job_id = resp.json().get("job_id")
            if not waf_job_id:
                return {"status": "failed", "error": "No job_id returned", "firewall": None}

            # Poll for completion (max 90s)
            deadline = _time.time() + 90
            while _time.time() < deadline:
                sr = requests.get(
                    f"{OSINT_RUNNER_URL}/jobs/{waf_job_id}",
                    headers={"x-api-key": API_KEY},
                    timeout=10,
                )
                if sr.status_code == 200:
                    data = sr.json()
                    if data.get("status") in ("completed", "failed"):
                        # Parse result to find WAF name
                        result = data.get("result", {})
                        output = data.get("output", "")
                        firewall = None

                        # Check ingest results for waf_detection findings
                        try:
                            from psycopg2.extras import RealDictCursor
                            with _db_conn() as c, c.cursor(cursor_factory=RealDictCursor) as cur:
                                cur.execute("""
                                    SELECT data->>'firewall' as firewall
                                    FROM recon_findings
                                    WHERE finding_type = 'waf_detection' AND target = %s
                                    ORDER BY created_at DESC LIMIT 1
                                """, (target_url,))
                                row = cur.fetchone()
                                if row and row.get("firewall"):
                                    firewall = row["firewall"]
                        except Exception:
                            pass

                        return {
                            "status": data.get("status", "completed"),
                            "firewall": firewall,
                            "waf_job_id": waf_job_id,
                        }
                _time.sleep(5)

            return {"status": "timeout", "firewall": None}

        except Exception as e:
            logger.warning(f"wafw00f failed: {e}")
            return {"status": "failed", "error": str(e), "firewall": None}

    def _run_katana(self, base_url: str, discovered_urls: List[str]) -> Dict[str, Any]:
        """
        Run Katana JS-aware crawler via pd-runner.

        Args:
            base_url: Base URL of the target
            discovered_urls: URLs discovered by previous stages

        Returns:
            Dict with 'urls_found' count and 'discovered_urls' list
        """
        result = {
            "urls_found": 0,
            "discovered_urls": []
        }

        # Build target list: base URL + discovered URLs (deduplicated)
        targets = list(set([base_url] + discovered_urls))

        try:
            response = self.client.post(
                f"{PD_RUNNER_URL}/jobs/katana",
                json={
                    "targets": targets,
                    "depth": 3,
                    "js_crawl": True
                },
                timeout=30.0
            )

            if response.status_code == 200:
                data = response.json()
                katana_job_id = data.get("job_id")
                logger.info(f"Katana scan started: job_id={katana_job_id}")

                if katana_job_id:
                    katana_result = self._wait_for_katana(katana_job_id)

                    # Parse output for discovered URLs
                    output = katana_result.get("output", "")
                    for line in output.splitlines():
                        line = line.strip()
                        if line and line.startswith(("http://", "https://")):
                            result["discovered_urls"].append(line)

                    # Deduplicate against already-known URLs
                    result["discovered_urls"] = list(set(result["discovered_urls"]) - set(discovered_urls))
                    result["urls_found"] = len(result["discovered_urls"])
            else:
                logger.warning(f"Katana scan start failed: HTTP {response.status_code}")

        except Exception as e:
            logger.warning(f"Katana scan error: {e}")

        return result

    def _wait_for_katana(self, job_id: str, timeout_sec: int = 600) -> Dict[str, Any]:
        """Wait for Katana scan to complete by polling pd-runner job status."""
        import time
        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            try:
                response = self.client.get(
                    f"{PD_RUNNER_URL}/jobs/{job_id}",
                    timeout=10.0
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("status")

                    if status in ("completed", "failed"):
                        return {
                            "status": status,
                            "output": data.get("output", "")
                        }

            except Exception as e:
                logger.warning(f"Error checking Katana status: {e}")

            time.sleep(10)  # Poll every 10s

        return {"status": "timeout", "output": ""}

    def _wait_for_nuclei(self, job_id: str, timeout_sec: int = 600) -> Dict[str, Any]:
        """Wait for Nuclei scan to complete"""
        import time
        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            try:
                response = self.client.get(
                    f"{NUCLEI_URL}/jobs/{job_id}",
                    timeout=10.0
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("status")

                    if status in ("completed", "failed"):
                        return {
                            "status": status,
                            "findings_count": data.get("progress", {}).get("findings_count", 0)
                        }

            except Exception as e:
                logger.warning(f"Error checking Nuclei status: {e}")

            time.sleep(15)  # Poll every 15s to reduce overhead

        return {"status": "timeout", "findings_count": 0}

    def close(self):
        """Close HTTP client"""
        self.client.close()
