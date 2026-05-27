"""Multi-stage scan pipeline orchestrator.

Drives Stages 0–5 for an engagement's scope. Each host progresses through
stages independently — as soon as Host A's masscan finishes, its nmap starts
even while Host B is still in masscan. All scan submissions go through the
same BFF scan-dispatch infra (scans.py + polling.py) so concurrency limits
and job tracking are respected.

Usage (from a BFF route):
    orch = PipelineOrchestrator(pipeline_id, engagement_id, config, targets)
    asyncio.create_task(orch.run())
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from config import get_settings
from polling import active_jobs, register_job, jobs_lock

log = logging.getLogger("pipeline")

# ── Stage constants ──────────────────────────────────────────────────────
STAGE_PASSIVE     = 0   # subfinder, dnsx, crtsh
STAGE_DISCOVERY   = 1   # masscan, httpx, naabu
STAGE_FINGERPRINT = 2   # nmap -sV per-host
STAGE_EXPLOIT     = 3   # nuclei, service-specific, web crawl
STAGE_AGGREGATE   = 4   # ZAP (seeded), nuclei 2nd pass, gowitness
STAGE_ANALYSIS    = 5   # OSINT agent, exploit matching, reporting

STAGE_NAMES = {
    0: "passive_recon",
    1: "discovery",
    2: "fingerprint",
    3: "exploit",
    4: "aggregate",
    5: "analysis",
}

# How many parallel jobs per stage (overridable via config.max_parallel_stage_N)
DEFAULT_PARALLEL = {
    STAGE_PASSIVE: 5,
    STAGE_DISCOVERY: 3,
    STAGE_FINGERPRINT: 20,
    STAGE_EXPLOIT: 15,
    STAGE_AGGREGATE: 5,
    STAGE_ANALYSIS: 3,
}

MAX_PIPELINE_CONCURRENT = int(os.environ.get("MAX_PIPELINE_CONCURRENT", "20"))

POLL_INTERVAL = float(os.environ.get("PIPELINE_POLL_INTERVAL", "5"))


class HostProgress:
    __slots__ = ("host", "stage", "status", "jobs", "ports", "services", "urls")

    def __init__(self, host: str):
        self.host = host
        self.stage = STAGE_PASSIVE
        self.status = "pending"      # pending | running | done | failed
        self.jobs: list[str] = []    # job_ids currently in-flight for this host
        self.ports: list[int] = []   # open ports from discovery
        self.services: list[dict] = []  # (port, service, banner) from nmap
        self.urls: list[str] = []    # HTTP URLs from httpx/katana/gobuster

    def to_dict(self) -> dict:
        return {
            "stage": self.stage,
            "stage_name": STAGE_NAMES.get(self.stage, "unknown"),
            "status": self.status,
            "jobs": self.jobs,
            "ports_found": len(self.ports),
            "services_found": len(self.services),
            "urls_found": len(self.urls),
        }


class PipelineOrchestrator:
    def __init__(
        self,
        pipeline_id: str,
        engagement_id: str,
        config: dict,
        targets: list[str],
        proxies: list[str] | None = None,
    ):
        self.pipeline_id = pipeline_id
        self.engagement_id = engagement_id
        self.config = config
        self.profile = config.get("profile", "pentest")
        self.targets = targets
        # Round-robin proxy assignment (SOCKS URLs from remote_nodes)
        self.proxies = proxies or []
        self._proxy_idx = 0
        self.hosts: dict[str, HostProgress] = {t: HostProgress(t) for t in targets}
        self._stopped = False
        self._settings = get_settings()
        self._api_key = self._settings.api_key
        self._rag_api = self._settings.rag_api_url
        self._jobs_spawned = 0
        self._jobs_completed = 0
        self._jobs_failed = 0
        self._skip_stages: set[int] = set(config.get("skip_stages") or [])

    # ── Proxy round-robin ────────────────────────────────────────────────
    def _next_proxy(self) -> str | None:
        if not self.proxies:
            return self.config.get("proxy") or None
        proxy = self.proxies[self._proxy_idx % len(self.proxies)]
        self._proxy_idx += 1
        return proxy

    # ── Persistence helpers ──────────────────────────────────────────────
    async def _update_pipeline(self, **fields: Any) -> None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                await c.patch(
                    f"{self._rag_api}/pipelines/{self.pipeline_id}",
                    json=fields,
                    headers={"x-api-key": self._api_key},
                )
        except Exception as e:
            log.warning("pipeline update failed: %s", e)

    async def _record_job(self, job_id: str, host: str, stage: int, scan_type: str) -> None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                await c.post(
                    f"{self._rag_api}/pipelines/{self.pipeline_id}/jobs",
                    json={"pipeline_id": self.pipeline_id, "job_id": job_id,
                          "host": host, "stage": stage, "scan_type": scan_type, "status": "running"},
                    headers={"x-api-key": self._api_key},
                )
        except Exception:
            pass

    async def _complete_job(self, job_id: str, status: str, result: dict | None = None) -> None:
        try:
            async with httpx.AsyncClient(verify=False, timeout=10) as c:
                await c.patch(
                    f"{self._rag_api}/pipelines/{self.pipeline_id}/jobs/{job_id}",
                    json={"status": status, "result": result},
                    headers={"x-api-key": self._api_key},
                )
        except Exception:
            pass

    # ── Scan dispatch ────────────────────────────────────────────────────
    async def _dispatch(self, scan_type: str, params: dict, host: str, stage: int) -> str | None:
        """Submit a scan via BFF /api/scans/{type} and return job_id."""
        if self._stopped:
            return None
        proxy = self._next_proxy()
        if proxy:
            params["proxy"] = proxy
        params.setdefault("engagement_id", self.engagement_id)
        try:
            async with httpx.AsyncClient(verify=False, timeout=60) as c:
                resp = await c.post(
                    f"https://127.0.0.1:{os.environ.get('BFF_PORT', '443')}/api/scans/{scan_type}",
                    json=params,
                    headers={"x-api-key": self._api_key, "Content-Type": "application/json"},
                )
                if resp.status_code >= 400:
                    log.warning("dispatch %s for %s failed: %s", scan_type, host, resp.text[:200])
                    return None
                data = resp.json()
                job_id = data.get("job_id")
        except Exception as e:
            log.warning("dispatch %s for %s error: %s", scan_type, host, e)
            return None

        if job_id:
            self._jobs_spawned += 1
            hp = self.hosts[host]
            hp.jobs.append(job_id)
            hp.status = "running"
            await self._record_job(job_id, host, stage, scan_type)
            log.info("[pipeline:%s] dispatched %s for %s → %s", self.pipeline_id[:8], scan_type, host, job_id[:8])
        return job_id

    # ── Wait for in-flight jobs on a host to complete ────────────────────
    async def _wait_host_jobs(self, host: str) -> None:
        hp = self.hosts[host]
        while hp.jobs and not self._stopped:
            still_running = []
            for jid in hp.jobs:
                info = active_jobs.get(jid)
                if not info:
                    self._jobs_completed += 1
                    await self._complete_job(jid, "completed")
                    continue
                st = info.get("status", "running")
                if st in ("completed", "failed", "stopped", "lost", "error"):
                    if st == "completed":
                        self._jobs_completed += 1
                    else:
                        self._jobs_failed += 1
                    await self._complete_job(jid, st, info.get("last_data"))
                else:
                    still_running.append(jid)
            hp.jobs = still_running
            if hp.jobs:
                await asyncio.sleep(POLL_INTERVAL)

    # ── Concurrency gate ─────────────────────────────────────────────────
    def _pipeline_active_count(self) -> int:
        count = 0
        for hp in self.hosts.values():
            count += len(hp.jobs)
        return count

    async def _wait_for_slot(self) -> None:
        while self._pipeline_active_count() >= MAX_PIPELINE_CONCURRENT and not self._stopped:
            await asyncio.sleep(1)

    # ── Stage implementations ────────────────────────────────────────────

    async def _stage_0_passive(self) -> None:
        """Passive recon: subfinder, dnsx, crtsh on domain targets."""
        if STAGE_PASSIVE in self._skip_stages:
            return
        domains = [t for t in self.targets
                   if not t.replace(".", "").replace(":", "").isdigit()
                   and "/" not in t and not t.startswith("http")]
        if not domains:
            return
        await self._update_pipeline(progress={"stage": "passive_recon", "domains": len(domains)})
        for tool in ("subfinder", "dnsx", "crtsh"):
            if self._stopped:
                return
            await self._wait_for_slot()
            target_key = "domains" if tool in ("subfinder", "dnsx") else "target"
            params = {target_key: domains if tool != "crtsh" else domains[0]}
            # Track under first domain for stage accounting
            host = domains[0]
            await self._dispatch(tool, params, host, STAGE_PASSIVE)

    async def _stage_1_discovery(self, host: str) -> None:
        """Fast port scan + HTTP probe for a single host."""
        if STAGE_DISCOVERY in self._skip_stages:
            return
        hp = self.hosts[host]
        hp.stage = STAGE_DISCOVERY
        hp.status = "running"
        # Masscan / nmap for port discovery
        await self._wait_for_slot()
        ports = self.config.get("ports", "1-65535")
        rate = self.config.get("rate", 1000)
        await self._dispatch("nmap", {"target": host, "ports": ports, "rate": rate}, host, STAGE_DISCOVERY)
        # Httpx in parallel (common web ports)
        await self._wait_for_slot()
        await self._dispatch("httpx", {"targets": host, "ports": "80,443,8080,8443,8000,8888,3000,5000"}, host, STAGE_DISCOVERY)

    async def _stage_2_fingerprint(self, host: str) -> None:
        """Nmap -sV already runs as part of the 'nmap' (masscan-then-nmap) scan type.
        Stage 2 is implicit — the dispatch in Stage 1 already does service detection.
        We just wait for those jobs and collect results here."""
        if STAGE_FINGERPRINT in self._skip_stages:
            return
        hp = self.hosts[host]
        hp.stage = STAGE_FINGERPRINT
        await self._wait_host_jobs(host)
        # Extract discovered ports/services from job results
        for jid in list(active_jobs.keys()):
            info = active_jobs.get(jid)
            if not info or info.get("type") not in ("nmap", "masscan-then-nmap", "masscan"):
                continue
            last = info.get("last_data") or {}
            # Ports from masscan/nmap results
            stats = (last.get("result") or last).get("stats") or {}
            if stats.get("total_ports"):
                hp.ports = list(range(stats.get("total_ports", 0)))  # placeholder
        hp.status = "done"

    async def _stage_3_exploit(self, host: str) -> None:
        """Service-specific scans + nuclei + web discovery."""
        if STAGE_EXPLOIT in self._skip_stages:
            return
        hp = self.hosts[host]
        hp.stage = STAGE_EXPLOIT
        hp.status = "running"
        # Nuclei on the host
        await self._wait_for_slot()
        await self._dispatch("nuclei", {"target": host, "severity": "medium,high,critical"}, host, STAGE_EXPLOIT)
        # Katana if HTTP ports
        await self._wait_for_slot()
        await self._dispatch("katana", {"targets": host}, host, STAGE_EXPLOIT)
        # Wait for all Stage 3 jobs
        await self._wait_host_jobs(host)
        hp.status = "done"

    async def _stage_4_aggregate(self, host: str) -> None:
        """ZAP seeded scan + screenshots."""
        if STAGE_AGGREGATE in self._skip_stages:
            return
        hp = self.hosts[host]
        hp.stage = STAGE_AGGREGATE
        hp.status = "running"
        # GoWitness screenshots
        await self._wait_for_slot()
        await self._dispatch("httpx", {"targets": host, "tech_detect": True}, host, STAGE_AGGREGATE)
        await self._wait_host_jobs(host)
        hp.status = "done"

    # ── Main loop ────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Execute the full pipeline. Each host progresses independently."""
        log.info("[pipeline:%s] starting for %d targets (profile=%s, proxies=%d)",
                 self.pipeline_id[:8], len(self.targets), self.profile, len(self.proxies))
        await self._update_pipeline(status="running")

        try:
            # Stage 0: passive (fire-and-forget, don't block)
            asyncio.create_task(self._stage_0_passive())
            await asyncio.sleep(0.5)

            # Stages 1-4: per-host progression
            sem = asyncio.Semaphore(MAX_PIPELINE_CONCURRENT)

            async def run_host(host: str) -> None:
                async with sem:
                    try:
                        await self._stage_1_discovery(host)
                        await self._wait_host_jobs(host)
                        await self._stage_2_fingerprint(host)
                        await self._stage_3_exploit(host)
                        await self._stage_4_aggregate(host)
                        self.hosts[host].stage = STAGE_ANALYSIS
                        self.hosts[host].status = "done"
                    except Exception as e:
                        log.error("[pipeline:%s] host %s failed: %s", self.pipeline_id[:8], host, e)
                        self.hosts[host].status = "failed"

                # Persist after each host
                await self._update_pipeline(
                    host_states={h: hp.to_dict() for h, hp in self.hosts.items()},
                    jobs_spawned=self._jobs_spawned,
                    jobs_completed=self._jobs_completed,
                    jobs_failed=self._jobs_failed,
                )

            # Launch all hosts concurrently (bounded by semaphore)
            await asyncio.gather(*[run_host(h) for h in self.targets])

            if self._stopped:
                await self._update_pipeline(status="stopped", completed_at=datetime.now(timezone.utc).isoformat())
            else:
                await self._update_pipeline(
                    status="completed",
                    completed_at=datetime.now(timezone.utc).isoformat(),
                    host_states={h: hp.to_dict() for h, hp in self.hosts.items()},
                    jobs_spawned=self._jobs_spawned,
                    jobs_completed=self._jobs_completed,
                    jobs_failed=self._jobs_failed,
                )
            log.info("[pipeline:%s] completed: %d spawned, %d completed, %d failed",
                     self.pipeline_id[:8], self._jobs_spawned, self._jobs_completed, self._jobs_failed)

        except Exception as e:
            log.exception("[pipeline:%s] fatal error", self.pipeline_id[:8])
            await self._update_pipeline(status="failed", error=str(e),
                                        completed_at=datetime.now(timezone.utc).isoformat())

    def stop(self) -> None:
        self._stopped = True
