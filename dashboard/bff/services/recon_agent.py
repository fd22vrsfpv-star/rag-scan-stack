"""Autonomous Recon Agent — background loop that ensures scope coverage.

For each enabled engagement, the agent periodically:
  1. Runs detection rules on recent findings (creates follow-ups)
  2. Checks for unresolved follow-ups with actionable scan suggestions
  3. Identifies scope targets missing scan coverage at each stage
  4. Auto-dispatches scans to fill coverage gaps
  5. Logs all decisions to campaign_events for audit trail

Started as an asyncio task from BFF lifespan (main.py). Controllable per
engagement via /api/recon-agent/* endpoints.
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from config import get_settings
from services.port_profiles import (
    PortProfileError,
    count_ports as count_profile_ports,
    resolve as resolve_port_profile,
)
from services.web_profiles import WebProfileError, resolve as resolve_web_profile

# Scan types a web depth profile shapes. Mirrors _WEB_PROFILE_SCANS in
# routers/scans.py; the BFF is authoritative, this just avoids sending the
# field on dispatches where it would be ignored.
WEB_PROFILE_SCANS = {
    "web", "pipeline", "nuclei", "gobuster", "katana", "nikto", "zap",
    "playwright", "content-recon", "httpx",
}

log = logging.getLogger("recon_agent")

BASE_INTERVAL = float(os.environ.get("RECON_AGENT_BASE_INTERVAL", "30"))

# The recon agent dispatches by calling the BFF's OWN API — a loopback self-call.
# Target uvicorn directly over plain HTTP on the internal port. nginx on :443
# serves a self-signed dashboard.crt that is NOT the stack CA, so httpx (which
# verifies) could never validate a loopback `https://127.0.0.1:443` call: EVERY
# dispatch failed with `CERTIFICATE_VERIFY_FAILED: self-signed certificate`, the
# agent recorded 0 dispatched and marked coverage failed. A loopback call into
# the same process needs no TLS.
BFF_INTERNAL_URL = os.environ.get("BFF_INTERNAL_URL", "http://127.0.0.1:8050")

# Scope names the agent must NEVER scan: hosts moved here are deliberately
# out-of-authorization (customer sites, operator exclusions). Kept separate from
# 'unknown_scope', which stays scannable until triaged.
RESERVED_NONSCANNABLE = {"customer_scope", "customer", "excluded", "not_in_scope"}

# Seed-stage discovery pipeline.
#
# Stages 0-2 (whois → dnsx → nmap) are the discovery seed that produces the
# port/service data the KB-driven dispatcher (Phase 4 in _agent_cycle) needs.
# Once nmap (stage 2) ingests, the post-ingest auto-recommender in rag-api
# (`_trigger_recommendations_for` at app/rag-api/api.py:1763) writes
# `scan_recommendations` rows per discovered port; Phase 4 then drains that
# queue, dispatching whichever tool the KB picked for each (ip, port, service)
# tuple.  This replaces the old hardcoded "stage 3 = httpx, stage 4 = nuclei"
# chain with KB-informed selection that adapts to what's actually on the wire.
#
# Stages 3 and 4 are retained as a LEGACY FALLBACK: operators can flip
# `config.kb_driven_recon=false` on the agent state to restore the old chain
# (useful when scan-recommender or its KB store is offline).
STAGE_TO_SCAN = {
    0: "whois",     # passive — WHOIS registration/ownership (no target contact)
    1: "dnsx",      # passive — DNS resolution (no target contact)
    2: "nmap",      # discovery (masscan-then-nmap, touches target)
    3: "httpx",     # legacy-only — replaced by KB dispatch when kb_driven_recon=true
    4: "nuclei",    # legacy-only — replaced by KB dispatch when kb_driven_recon=true
}

# Stages that always run regardless of kb_driven_recon — they produce the
# port data the KB needs.  Stages NOT in this set are legacy-only.
SEED_STAGES = {0, 1, 2}

STAGE_NAMES = {0: "passive-whois", 1: "passive-dns", 2: "discovery", 3: "fingerprint", 4: "exploit"}

# Which target types each scan applies to. If a scan isn't listed here, it runs on all types.
# Configurable per-engagement via config.scan_target_types override.
SCAN_TARGET_TYPES: dict[str, set[str]] = {
    "whois": {"domain", "ip"},
    "dnsx": {"domain"},               # DNS resolution only makes sense for domains
    "subfinder": {"domain"},           # subdomain enum only for domains
    "nmap": {"ip", "cidr", "domain"},
    "httpx": {"ip", "domain", "url"},
    "nuclei": {"ip", "domain", "url"},
}

# Default for whether a cycle should drain the KB recommendation queue
# (Phase 4 below) or fall back to the legacy hardcoded stage 3/4 dispatches.
# Operators can override per-engagement via `config.kb_driven_recon=false`.
KB_DRIVEN_RECON_DEFAULT = True

import re as _re
_IP_RE = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_CIDR_RE = _re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')


def _guess_target_type(target: str) -> str:
    """Guess whether a target is a domain, IP, CIDR, or URL."""
    t = target.strip()
    if _CIDR_RE.match(t):
        return "cidr"
    if _IP_RE.match(t):
        return "ip"
    if t.startswith("http://") or t.startswith("https://"):
        return "url"
    return "domain"


MAX_CONCURRENT_RECON_SCANS = int(os.environ.get("RECON_AGENT_MAX_CONCURRENT", "3"))

# Engagement-scoping predicate for pending KB recommendations.
#
# Shared verbatim by the drain's fetch and by the queue-depth COUNT, so the depth
# the operator is shown can never drift from the rows the drain actually
# considers. Takes the engagement id TWICE (assets path, then scope_targets path).
#
# host() on both sides of the ip comparison: sr.ip is inet and renders as
# "192.168.1.150/32", while scope_targets.target is plain text "192.168.1.150".
_KB_PENDING_SCOPE_SQL = """
          FROM scan_recommendations sr
         WHERE sr.status = 'pending'
           AND sr.ip IS NOT NULL
           AND (
                 sr.ip IN (
                   SELECT a.ip FROM assets a
                    WHERE a.engagement_id = %s::uuid
                      AND a.ip IS NOT NULL
                 )
                 OR EXISTS (
                   SELECT 1 FROM scope_targets st
                    WHERE st.engagement_id = %s::uuid
                      AND st.target <> ''
                      AND (
                        (st.target_type = 'ip'
                          AND host(sr.ip)::text = st.target)
                        OR (st.target_type = 'cidr'
                          AND st.target ~ '^[0-9]+([.][0-9]+){3}/[0-9]+$'
                          AND sr.ip <<= st.target::inet)
                      )
                 )
               )
"""


# How many times a recommendation may fail transiently before it is retired.
# Retiring on the FIRST failure would discard valid recon work whenever a scanner
# container happened to be restarting; never retiring lets a permanently broken
# rec sit at the head of the priority-ordered queue and consume the budget
# forever. Three attempts distinguishes a blip from a broken rec.
MAX_DISPATCH_ATTEMPTS = int(os.environ.get("RECON_AGENT_MAX_DISPATCH_ATTEMPTS", "3"))

# Failure details that will NEVER succeed on an identical retry.
_PERMANENT_FAILURE_MARKERS = (
    "not in allowed list",
    "no automated handler",
    "manual tool",
    "unknown scanner",
    "not supported",
)

# Transport-level failures — the request never got a verdict, so it is retryable.
_TRANSIENT_EXC_MARKERS = (
    "connecterror", "connecttimeout", "readtimeout", "readerror",
    "pooltimeout", "remoteprotocolerror", "timeout", "connection refused",
)

_HTTP_CODE_RE = _re.compile(r"HTTP (\d{3})")


def _is_permanent_dispatch_failure(detail: str) -> bool:
    """Should this failed rec be retired, or retried next cycle?

    Conservative by design: anything unrecognised is treated as TRANSIENT and
    stays pending. Wrongly retrying costs one dispatch slot; wrongly retiring
    silently drops a recommendation the operator never learns about. The attempt
    counter (MAX_DISPATCH_ATTEMPTS) is what stops an unrecognised-but-permanent
    failure from blocking the queue indefinitely.
    """
    raw = detail or ""
    d = raw.lower()

    if any(m in d for m in _PERMANENT_FAILURE_MARKERS):
        return True

    m = _HTTP_CODE_RE.search(raw)
    if m:
        code = int(m.group(1))
        # 408 Request Timeout and 429 Too Many Requests are explicitly retryable
        # despite being 4xx.
        if code in (408, 429):
            return False
        # Any other 4xx means the REQUEST is wrong; resending it unchanged gives
        # the same answer. 5xx is the server's problem and may clear.
        return 400 <= code < 500

    if any(t in d for t in _TRANSIENT_EXC_MARKERS):
        return False

    return False


class ReconAgent:
    def __init__(self):
        self._stopped = False
        self._settings = get_settings()

    async def run(self):
        """Main loop. Polls every BASE_INTERVAL seconds for enabled engagements."""
        log.info("Recon agent started (base_interval=%.0fs)", BASE_INTERVAL)
        while not self._stopped:
            try:
                await self._tick()
            except Exception:
                log.exception("Recon agent tick error")
            await asyncio.sleep(BASE_INTERVAL)
        log.info("Recon agent stopped")

    def stop(self):
        self._stopped = True

    async def _tick(self):
        """One tick: fetch all enabled agents, run cycle for those due."""
        s = self._settings
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(
                    f"{s.rag_api_url}/recon-agent/all/enabled",
                    headers={"x-api-key": s.api_key},
                )
                if resp.status_code != 200:
                    return
                agents = resp.json().get("agents", [])
        except Exception as e:
            log.debug("Failed to fetch enabled agents: %s", e)
            return

        now = time.time()
        for agent in agents:
            eid = agent.get("engagement_id")
            if not eid:
                continue
            # Check pause
            pause_until = agent.get("pause_until")
            if pause_until:
                try:
                    pu = datetime.fromisoformat(pause_until.replace("Z", "+00:00"))
                    if pu > datetime.now(timezone.utc):
                        continue
                except Exception:
                    pass
            # Check interval
            interval = agent.get("interval_sec", 300)
            last_run = agent.get("last_run_at")
            if last_run:
                try:
                    lr = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                    elapsed = (datetime.now(timezone.utc) - lr).total_seconds()
                    if elapsed < interval:
                        continue
                except Exception:
                    pass

            # Check global concurrent scan limit before running cycle
            from polling import active_jobs
            running_count = sum(1 for j in active_jobs.values()
                                if j.get("status") in ("running", "queued"))
            if running_count >= MAX_CONCURRENT_RECON_SCANS:
                log.info("Agent tick: skipping %s — %d scans already running (max %d)",
                         eid[:8], running_count, MAX_CONCURRENT_RECON_SCANS)
                continue

            log.info("Agent tick: running cycle for %s (%s) [%d/%d running]",
                     eid[:8], agent.get("engagement_name", "?"),
                     running_count, MAX_CONCURRENT_RECON_SCANS)
            try:
                await self._agent_cycle(eid, agent.get("config") or {}, agent)
            except Exception:
                log.exception("Agent cycle failed for engagement %s", eid[:8] if eid else "?")

    async def _emit_webhook(self, eid: str, event_type: str, headers: dict,
                             data: dict, severity: str | None = None) -> None:
        """Emit a webhook event via rag-api's webhook dispatcher."""
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                payload = {"event_type": event_type, "source": "recon_agent", "data": data}
                if severity:
                    payload["severity"] = severity
                await c.post(
                    f"{self._settings.rag_api_url}/webhooks/emit",
                    json=payload, headers=headers,
                )
        except Exception:
            pass  # fire-and-forget

    async def _agent_cycle(self, eid: str, config: dict, agent_state: dict):
        """One cycle for one engagement."""
        s = self._settings
        headers = {"x-api-key": s.api_key}
        profile = config.get("profile", "pentest")
        interval = agent_state.get("interval_sec", 300)
        max_dispatches = config.get("max_dispatches_per_cycle", 5 if profile == "pentest" else 2)
        dispatched = 0
        # KB-driven recon: skip the legacy hardcoded stage 3 (httpx) / stage 4
        # (nuclei) dispatches and instead drain the scan_recommendations queue
        # in Phase 4 below.  The queue is populated by rag-api's post-ingest
        # auto-recommender after each nmap/discovery scan ingests, so the KB
        # picks the right tool per discovered (ip, port, service).
        kb_driven_recon = bool(config.get("kb_driven_recon", KB_DRIVEN_RECON_DEFAULT))

        # Port scope for this cycle's network scans.  Resolved here for logging
        # and telemetry only — the profile id itself is what gets sent to the
        # BFF, which owns resolution (see the dispatch block below).
        port_profile = (config.get("port_profile") or "").strip().lower() or None
        resolved_ports: Optional[str] = None
        if port_profile:
            try:
                resolved_ports = resolve_port_profile(port_profile, config.get("ports"))
            except PortProfileError as e:
                # Don't abort the cycle: the dispatch below will surface the
                # same error per-scan through the existing 400 path, which
                # already logs and emits recon_agent_blocked.
                log.error("[recon:%s] bad port_profile %r: %s", eid[:8], port_profile, e)

        # Web scan depth for this cycle's web-tool dispatches (httpx/nuclei and
        # anything the KB queue picks). Validated here so a bad id is logged once
        # per cycle rather than once per dispatch.
        web_profile = (config.get("web_profile") or "").strip().lower() or None
        if web_profile and web_profile != "custom":
            try:
                resolve_web_profile(web_profile)
            except WebProfileError as e:
                log.error("[recon:%s] bad web_profile %r: %s", eid[:8], web_profile, e)
                web_profile = None

        # Resolve proxy / tunnel config
        proxy_single = config.get("proxy")  # explicit single proxy URL
        use_tunnels = config.get("use_tunnels", False)
        exclude_set = set(config.get("exclude_tunnels") or [])  # URLs to skip
        tunnel_proxies: list[str] = []
        if use_tunnels:
            try:
                async with httpx.AsyncClient(timeout=5) as c:
                    nr = await c.get(f"{s.tunnel_manager_url}/nodes", headers=headers)
                    if nr.status_code == 200:
                        for node in (nr.json().get("nodes") or []):
                            if node.get("status") == "online" and node.get("proxy_port"):
                                url = f"socks5://host.docker.internal:{node['proxy_port']}"
                                if url not in exclude_set:
                                    tunnel_proxies.append(url)
                                else:
                                    log.debug("[recon:%s] excluding tunnel %s (%s)",
                                              eid[:8], node.get("name"), url)
            except Exception as e:
                log.warning("[recon:%s] tunnel fetch failed: %s", eid[:8], e)
        self._tunnel_idx = 0

        # Resolve where generic (non-native-runner) tools should execute.
        # OPSEC: all OFF by default — opt-in per engagement.  use_kali runs them
        # in the internal Kali container; use_nodes_for_tools round-robins them
        # across online tunneled nodes (or tool_node_id pins one).  The dispatch
        # endpoint preflights + auto-installs the tool on the chosen executor.
        use_kali = bool(config.get("use_kali", False))
        use_nodes_for_tools = bool(config.get("use_nodes_for_tools", False))
        explicit_tool_node = config.get("tool_node_id")
        exclude_tool_nodes = set(config.get("exclude_tool_nodes") or [])
        tool_node_ids: list[str] = []
        if use_nodes_for_tools and not explicit_tool_node:
            try:
                async with httpx.AsyncClient(timeout=5) as c:
                    nr = await c.get(f"{s.tunnel_manager_url}/nodes", headers=headers)
                    if nr.status_code == 200:
                        for node in (nr.json().get("nodes") or []):
                            if node.get("status") == "online" and node.get("id") not in exclude_tool_nodes:
                                tool_node_ids.append(node["id"])
            except Exception as e:
                log.warning("[recon:%s] tool-node fetch failed: %s", eid[:8], e)
        self._tool_node_idx = 0

        log.info("[recon:%s] starting cycle (profile=%s, port_scope=%s, interval=%ds, tunnels=%d, proxy=%s, use_kali=%s, tool_nodes=%d)",
                 eid[:8], profile, port_profile or config.get("ports") or "default",
                 interval, len(tunnel_proxies), proxy_single or "none",
                 use_kali, len(tool_node_ids))

        # Webhook: port scope in effect for this cycle.  Emitted once per cycle
        # (not per dispatch) so subscribers can see the scan scope without
        # having to infer it from every individual dispatch event.
        if port_profile:
            await self._emit_webhook(eid, "port_profile_applied", headers, {
                "engagement_id": eid,
                "port_profile": port_profile,
                "ports": resolved_ports,
                "port_count": count_profile_ports(resolved_ports) if resolved_ports else None,
                "profile": profile,
            })
        if web_profile:
            await self._emit_webhook(eid, "web_profile_applied", headers, {
                "engagement_id": eid,
                "web_profile": web_profile,
                "profile": profile,
            })

        # 0. Update stale "running" coverage entries — check if their jobs actually finished
        from polling import active_jobs
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(f"{s.rag_api_url}/recon-agent/{eid}/coverage",
                                   headers=headers)
                if resp.status_code == 200:
                    for cov in resp.json().get("coverage", []):
                        if cov["status"] != "running" or not cov.get("job_id"):
                            continue
                        # Check if the job is still active in BFF polling
                        job_info = active_jobs.get(cov["job_id"])
                        if job_info:
                            job_status = job_info.get("status", "running")
                            if job_status in ("completed", "failed", "stopped", "lost", "error"):
                                new_status = "completed" if job_status == "completed" else "failed"
                                try:
                                    await c.patch(
                                        f"{s.rag_api_url}/recon-agent/{eid}/coverage/{cov['id']}",
                                        json={"status": new_status, "completed_at": datetime.now(timezone.utc).isoformat()},
                                        headers=headers,
                                    )
                                except Exception:
                                    pass
                        else:
                            # Job not tracked anymore — mark as completed (it ran and finished before we could check)
                            try:
                                await c.patch(
                                    f"{s.rag_api_url}/recon-agent/{eid}/coverage/{cov['id']}",
                                    json={"status": "completed", "completed_at": datetime.now(timezone.utc).isoformat()},
                                    headers=headers,
                                )
                            except Exception:
                                pass
        except Exception:
            pass

        # Webhook: cycle started
        await self._emit_webhook(eid, "recon_agent_cycle_started", headers, {
            "engagement_id": eid, "profile": profile, "interval": interval,
            "tunnels": len(tunnel_proxies), "proxy": proxy_single,
        })

        # 1. Run detection rules on recent findings
        since_minutes = max(1, interval // 60 + 1)
        try:
            async with httpx.AsyncClient(timeout=60) as c:
                resp = await c.post(
                    f"{s.rag_api_url}/agent/scan",
                    params={"since_minutes": since_minutes, "engagement_id": eid},
                    headers=headers,
                )
                if resp.status_code == 200:
                    scan_result = resp.json()
                    log.info("[recon:%s] rule scan: %s", eid[:8], scan_result)
        except Exception as e:
            log.warning("[recon:%s] rule scan failed: %s", eid[:8], e)

        # 2. Check unresolved follow-ups
        open_followups = []
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(
                    f"{s.rag_api_url}/follow-ups",
                    params={"status": "open", "engagement_id": eid, "limit": 50},
                    headers=headers,
                )
                if resp.status_code == 200:
                    open_followups = resp.json().get("items", [])
        except Exception as e:
            log.debug("[recon:%s] follow-up fetch failed: %s", eid[:8], e)

        # 3. Check scope coverage gaps
        # If config specifies scope_names, only scan those scopes. Otherwise scan all.
        allowed_scopes = config.get("scope_names") or []  # e.g. ["external", "dmz"]
        targets = []           # list of target strings
        target_types = {}      # target -> type (domain/ip/cidr/url)
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(
                    f"{s.rag_api_url}/engagements/{eid}/scopes",
                    headers=headers,
                )
                if resp.status_code == 200:
                    for scope in resp.json().get("scopes", []):
                        if scope["name"] in RESERVED_NONSCANNABLE:
                            continue  # never scan customer/excluded buckets
                        if allowed_scopes and scope["name"] not in allowed_scopes:
                            continue
                        r2 = await c.get(
                            f"{s.rag_api_url}/engagements/{eid}/scopes/{scope['name']}",
                            headers=headers,
                        )
                        if r2.status_code == 200:
                            for t in r2.json().get("targets", []):
                                if t.get("target"):
                                    tgt = t["target"]
                                    targets.append(tgt)
                                    # Use API-provided type, fall back to guessing
                                    target_types[tgt] = t.get("target_type") or _guess_target_type(tgt)
        except Exception as e:
            log.debug("[recon:%s] scope fetch failed: %s", eid[:8], e)

        # Get existing coverage (DB records of completed/running scans)
        # Skip stale "running" records older than 2h — treat as failed so they can be retried
        coverage_set: set[tuple[str, int, str]] = set()
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                # First: reset stale running records
                try:
                    await c.post(
                        f"{s.rag_api_url}/recon-agent/{eid}/coverage/cleanup-stale",
                        headers=headers,
                    )
                except Exception:
                    pass
                resp = await c.get(
                    f"{s.rag_api_url}/recon-agent/{eid}/coverage",
                    headers=headers,
                )
                if resp.status_code == 200:
                    for cov in resp.json().get("coverage", []):
                        # Only count completed as done; failed/running can be retried
                        if cov.get("status") == "completed":
                            coverage_set.add((cov["target"], cov["stage"], cov.get("scan_type", "")))
        except Exception:
            pass

        # Also check currently in-flight scans (active_jobs) to avoid duplicates.
        # A scan may be running but not yet recorded as coverage (race window).
        from polling import active_jobs
        in_flight_targets: set[tuple[str, str]] = set()  # (target, scan_type)
        for jid, info in list(active_jobs.items()):
            if info.get("status") in ("running", "queued"):
                jt = info.get("target") or ""
                st = info.get("type") or ""
                if jt and st:
                    in_flight_targets.add((jt, st))

        # 4. Dispatch scans stage-by-stage (passive first, then quick, then deep)
        # Complete each stage across all targets before moving to the next
        skip_stages = set(config.get("skip_stages", []))
        # Allow per-engagement override of scan-target-type mappings
        custom_scan_types = config.get("scan_target_types", {})
        for stage, scan_type in sorted(STAGE_TO_SCAN.items()):
            if stage in skip_stages:
                continue
            # KB-driven mode: post-discovery stages (httpx, nuclei) are owned
            # by Phase 4's KB-queue drain.  Skip them here so the agent doesn't
            # double-dispatch on top of whatever the KB recommended.
            if kb_driven_recon and stage not in SEED_STAGES:
                continue

            # Filter targets to those compatible with this scan type
            allowed_types = custom_scan_types.get(scan_type) or SCAN_TARGET_TYPES.get(scan_type)
            if allowed_types:
                allowed_set = set(allowed_types) if isinstance(allowed_types, list) else allowed_types
                applicable_targets = [t for t in targets if target_types.get(t, "domain") in allowed_set]
            else:
                applicable_targets = targets  # no restriction

            # Check if this stage is complete across applicable targets
            stage_remaining = [t for t in applicable_targets if (t, stage, scan_type) not in coverage_set]
            if not stage_remaining:
                continue  # stage done, move to next

            # Don't start later stages until earlier ones are complete for applicable targets
            if stage > 0:
                prev_stage = stage - 1
                prev_type = STAGE_TO_SCAN.get(prev_stage)
                if prev_type and prev_stage not in skip_stages:
                    prev_allowed = custom_scan_types.get(prev_type) or SCAN_TARGET_TYPES.get(prev_type)
                    if prev_allowed:
                        prev_applicable = [t for t in targets if target_types.get(t, "domain") in (set(prev_allowed) if isinstance(prev_allowed, list) else prev_allowed)]
                    else:
                        prev_applicable = targets
                    prev_incomplete = [t for t in prev_applicable if (t, prev_stage, prev_type) not in coverage_set]
                    if prev_incomplete:
                        log.debug("[recon:%s] stage %d (%s) waiting — stage %d has %d targets remaining",
                                  eid[:8], stage, scan_type, prev_stage, len(prev_incomplete))
                        break  # don't start this stage yet

            for target in stage_remaining:
                if dispatched >= max_dispatches:
                    break
                # Respect global concurrent limit
                current_running = sum(1 for j in active_jobs.values()
                                      if j.get("status") in ("running", "queued"))
                if current_running >= MAX_CONCURRENT_RECON_SCANS:
                    log.info("[recon:%s] stopping — hit max concurrent (%d)",
                             eid[:8], MAX_CONCURRENT_RECON_SCANS)
                    break
                # Skip if already in-flight
                if (target, scan_type) in in_flight_targets:
                    log.debug("[recon:%s] skipping %s for %s — already in-flight", eid[:8], scan_type, target)
                    continue

                # Throttle: 5s between dispatches (prevents flooding)
                if dispatched > 0:
                    await asyncio.sleep(5)

                # Redteam jitter
                if profile == "redteam":
                    jitter = random.uniform(0, 120)
                    await asyncio.sleep(jitter)

                # Record coverage as running
                try:
                    async with httpx.AsyncClient(timeout=10) as c:
                        await c.post(
                            f"{s.rag_api_url}/recon-agent/{eid}/coverage",
                            json={"target": target, "stage": stage,
                                  "stage_name": STAGE_NAMES.get(stage, ""),
                                  "scan_type": scan_type, "status": "running"},
                            headers=headers,
                        )
                except Exception:
                    pass

                # Dispatch scan — route through tunnel if configured
                try:
                    # Pick proxy: round-robin tunnels > explicit single > none
                    scan_proxy = None
                    if tunnel_proxies:
                        scan_proxy = tunnel_proxies[self._tunnel_idx % len(tunnel_proxies)]
                        self._tunnel_idx += 1
                    elif proxy_single:
                        scan_proxy = proxy_single

                    # Normalize target: strip URL to hostname for network scans
                    scan_target = target
                    if scan_type in ("nmap", "masscan-then-nmap", "nmap-tcp", "nuclei", "httpx"):
                        if scan_target.startswith("http://") or scan_target.startswith("https://"):
                            try:
                                from urllib.parse import urlparse
                                scan_target = urlparse(scan_target).hostname or scan_target
                            except Exception:
                                pass

                    async with httpx.AsyncClient(timeout=60) as c:
                        # Use target_url for web scans, target for network scans
                        if scan_type in ("web", "gobuster", "nikto", "katana", "playwright", "pipeline"):
                            payload = {"target_url": target, "engagement_id": eid}
                        else:
                            payload = {"target": scan_target, "engagement_id": eid}
                        if scan_proxy:
                            payload["proxy"] = scan_proxy
                        # Port scope.  Preferred form is a named profile
                        # (config.port_profile: top-100 / top-1000 / web / all),
                        # which the BFF resolves into an explicit port string —
                        # see services/port_profiles.py.  Sending the profile id
                        # rather than a resolved string keeps resolution in one
                        # place and lets an unknown id surface through the
                        # existing 400 handling below.
                        #
                        # Legacy configs (enabled before profiles existed) carry
                        # a literal config.ports string and keep working
                        # unchanged, including "--top-ports N".
                        if scan_type in ("nmap", "masscan-then-nmap", "nmap-tcp"):
                            if port_profile:
                                payload["port_profile"] = port_profile
                                if port_profile == "custom" and config.get("ports"):
                                    payload["ports"] = config["ports"]
                            else:
                                payload["ports"] = config.get("ports", "--top-ports 1000")

                        # Web scan depth. Same contract as the port profile: the
                        # BFF resolves the id, so an unknown one surfaces through
                        # the existing 400 handling rather than failing silently.
                        if web_profile and scan_type in WEB_PROFILE_SCANS:
                            payload["web_profile"] = web_profile
                        resp = await c.post(
                            f"{BFF_INTERNAL_URL}/api/scans/{scan_type}",
                            json=payload,
                            headers={**headers, "Content-Type": "application/json"},
                        )
                        if resp.status_code < 400:
                            job_id = resp.json().get("job_id", "")
                            dispatched += 1
                            log.info("[recon:%s] dispatched %s for %s → %s (stage %d)",
                                     eid[:8], scan_type, target, job_id[:8] if job_id else "?", stage)
                            # Webhook: scan dispatched
                            await self._emit_webhook(eid, "recon_agent_scan_dispatched", headers, {
                                "engagement_id": eid, "target": target, "scan_type": scan_type,
                                "stage": stage, "job_id": job_id, "proxy": scan_proxy,
                                "port_profile": port_profile,
                                "ports": payload.get("ports") or resolved_ports,
                            })

                            # Update coverage with job_id
                            try:
                                async with httpx.AsyncClient(timeout=10) as c2:
                                    await c2.post(
                                        f"{s.rag_api_url}/recon-agent/{eid}/coverage",
                                        json={"target": target, "stage": stage,
                                              "stage_name": STAGE_NAMES.get(stage, ""),
                                              "scan_type": scan_type, "job_id": job_id,
                                              "status": "running"},
                                        headers=headers,
                                    )
                            except Exception:
                                pass
                        elif resp.status_code == 403 and "local scans are blocked" in resp.text.lower():
                            # Block-local-scans safety switch is on and we have no proxy.
                            # Auto-disable the agent — no point cycling if every dispatch gets rejected.
                            log.error(
                                "[recon:%s] LOCAL SCANS BLOCKED — agent has no proxy/tunnel configured. "
                                "Auto-disabling agent for this engagement. Configure a tunnel in "
                                "Engagements → Recon Agent tab, or disable 'Block local scans' in Settings.",
                                eid[:8],
                            )
                            await self._emit_webhook(eid, "recon_agent_auto_disabled", headers, {
                                "engagement_id": eid,
                                "reason": "Local scans are blocked and no proxy/tunnel is configured. "
                                          "Agent disabled itself to avoid noisy 403 loops. "
                                          "Fix: configure a tunnel on the Recon Agent, or disable "
                                          "'Block local scans' in Settings → General.",
                            }, severity="high")
                            # Log to campaign events
                            try:
                                async with httpx.AsyncClient(timeout=10) as c3:
                                    await c3.post(
                                        f"{s.rag_api_url}/engagements/{eid}/campaign-events",
                                        json={
                                            "kill_chain_phase": "reconnaissance",
                                            "title": "Recon agent auto-disabled: local scans blocked",
                                            "description": (
                                                "The agent has no proxy/tunnel configured but 'Block local scans' "
                                                "is enabled. All scan dispatches are being rejected (HTTP 403). "
                                                "Agent disabled itself. Re-enable after configuring a tunnel."
                                            ),
                                            "operator": "recon_agent",
                                            "detected": False,
                                        },
                                        headers=headers,
                                    )
                            except Exception:
                                pass
                            # Disable the agent
                            try:
                                async with httpx.AsyncClient(timeout=10) as c3:
                                    await c3.post(
                                        f"{s.rag_api_url}/recon-agent/{eid}/disable",
                                        headers=headers,
                                    )
                            except Exception:
                                pass
                            return  # exit this cycle immediately
                        else:
                            log.warning("[recon:%s] dispatch %s for %s failed: %s",
                                        eid[:8], scan_type, target, resp.text[:200])
                            # Webhook: dispatch blocked/failed
                            await self._emit_webhook(eid, "recon_agent_blocked", headers, {
                                "engagement_id": eid, "target": target, "scan_type": scan_type,
                                "reason": resp.text[:300], "status_code": resp.status_code,
                            }, severity="warning")
                except Exception as e:
                    log.warning("[recon:%s] dispatch error: %s", eid[:8], e)

                if dispatched >= max_dispatches:
                    break

        # 4b. Phase 4 — drain the KB recommendation queue (kb_driven_recon=true)
        #
        # After the seed pipeline (stages 0-2) runs nmap, the post-ingest auto-
        # recommender in rag-api (`_trigger_recommendations_for` at
        # app/rag-api/api.py:1763) writes scan_recommendations rows per
        # discovered (ip, port, service) tuple.  Phase 4 dispatches those recs
        # via the existing /api/scan-recommendations/run endpoint, which
        # already handles SCANNER_URLS routing, the Piece-1 status writeback
        # loop, idempotency against in-flight jobs, and per-scanner manual-
        # tool fallback (kali/node).  We just pick a proxy (matching the
        # legacy dispatcher's policy) and submit the batch.
        #
        # Scoping: scan_recommendations has no engagement_id column; recs
        # link to assets.id which has engagement_id.  Query through the join
        # so we only drain THIS engagement's pending recs.
        kb_drained = 0
        kb_skipped_pending = 0
        kb_total_pending = 0
        kb_failed = 0
        if kb_driven_recon and dispatched < max_dispatches:
            pending_recs: list[dict] = []
            try:
                from db import get_db
                budget = max_dispatches - dispatched
                # Pull priority-ordered pending recs scoped to this engagement.
                # Fetch slightly more than budget so we have something to
                # report under kb_skipped_pending when the queue's deeper
                # than this cycle can drain.
                with get_db() as conn, conn.cursor() as cur:
                    # IMPORTANT: query by IP membership, not asset_id JOIN.
                    # scan_recommender's `persist_recommendations` historically
                    # inserts with asset_id=NULL (the /next_scan callers don't
                    # resolve the IP -> asset_id mapping before persisting), so
                    # joining on sr.asset_id would skip every rec.  Subselect
                    # for the engagement's asset IPs keeps the scoping correct
                    # without depending on the FK being populated.
                    # Scoped by the engagement's SCOPE as well as by stamped
                    # assets. assets.engagement_id alone was not enough: with 166
                    # pending recommendations for 192.168.1.150 and that IP sitting
                    # in the engagement's scope_targets, this query returned ZERO,
                    # because no asset row had ever been stamped with an
                    # engagement_id. The queue could not drain no matter how often
                    # the agent ran.
                    #
                    # scope_targets IS reliably populated (it is what the operator
                    # enters), so it is the authoritative answer to "does this IP
                    # belong to this engagement". Assets are kept in the OR as the
                    # faster path for when the FK is populated.
                    #
                    # host() on both sides: sr.ip is inet and renders as
                    # "192.168.1.150/32", while scope_targets.target is plain text
                    # "192.168.1.150" — comparing them raw never matches.
                    cur.execute(
                        """
                        SELECT sr.id::text, host(sr.ip)::text, sr.service,
                               sr.scanner, sr.action, sr.script, sr.template,
                               sr.priority
                        """
                        + _KB_PENDING_SCOPE_SQL
                        + """
                         ORDER BY sr.priority ASC, sr.created_at DESC
                         LIMIT %s
                        """,
                        (eid, eid, max(budget * 3, 10)),
                    )
                    pending_recs = [
                        {"id": r[0], "ip": r[1], "service": r[2],
                         "scanner": r[3], "action": r[4], "script": r[5],
                         "template": r[6], "priority": r[7]}
                        for r in cur.fetchall()
                    ]
                    # TRUE queue depth, not the fetch window.
                    #
                    # The fetch is LIMITed to max(budget*3, 10), so deriving the
                    # remainder from len(pending_recs) capped the reported backlog
                    # at ~13 no matter how deep the queue really was — it read as
                    # "nearly drained" while 144 recs were outstanding, and it
                    # could never show the queue GROWING faster than it drains,
                    # which is the condition worth alerting on.
                    cur.execute("SELECT count(*) " + _KB_PENDING_SCOPE_SQL,
                                (eid, eid))
                    kb_total_pending = int(cur.fetchone()[0] or 0)
            except Exception as e:
                log.warning("[recon:%s] KB queue fetch failed: %s",
                            eid[:8], e)

            if pending_recs:
                # Respect both budgets: per-cycle (max_dispatches) AND the
                # global concurrent-scan cap.
                current_running = sum(
                    1 for j in active_jobs.values()
                    if j.get("status") in ("running", "queued")
                )
                kb_budget = max(0, min(
                    max_dispatches - dispatched,
                    MAX_CONCURRENT_RECON_SCANS - current_running,
                ))
                recs_to_dispatch = pending_recs[:kb_budget]
                kb_skipped_pending = max(
                    0, len(pending_recs) - len(recs_to_dispatch)
                )

                if recs_to_dispatch:
                    # Pick proxy with the same round-robin / single-proxy
                    # policy the legacy seed loop uses above.  All recs in
                    # this batch share the same proxy — keeps the runner
                    # behavior consistent within a cycle.
                    kb_proxy = None
                    if tunnel_proxies:
                        kb_proxy = tunnel_proxies[
                            self._tunnel_idx % len(tunnel_proxies)
                        ]
                        self._tunnel_idx += 1
                    elif proxy_single:
                        kb_proxy = proxy_single

                    # Pick a tool-dispatch target for generic (non-native)
                    # tools: explicit node, else round-robin over online nodes.
                    kb_node_id = explicit_tool_node
                    if not kb_node_id and tool_node_ids:
                        kb_node_id = tool_node_ids[self._tool_node_idx % len(tool_node_ids)]
                        self._tool_node_idx += 1

                    payload = {"ids": [r["id"] for r in recs_to_dispatch]}
                    if kb_proxy:
                        payload["proxy"] = kb_proxy
                    if use_kali:
                        payload["use_kali"] = True
                    if kb_node_id:
                        payload["node_id"] = kb_node_id

                    try:
                        # Self-call into the BFF dispatch endpoint — same
                        # pattern the legacy loop uses (cf. /api/scans/<type>
                        # invocation above).  Pass engagement explicitly so
                        # the downstream handler's engagement_headers()
                        # resolves correctly regardless of middleware state
                        # on this background task.
                        async with httpx.AsyncClient(timeout=120) as c:
                            resp = await c.post(
                                f"{BFF_INTERNAL_URL}/api/scan-recommendations/run",
                                json=payload,
                                headers={
                                    **headers,
                                    "Content-Type": "application/json",
                                    "x-engagement-id": eid,
                                },
                            )
                        if resp.status_code < 400:
                            body = resp.json() or {}
                            skipped_rec_ids: list[str] = []
                            failed_rec_ids: list[str] = []
                            transient_rec_ids: list[str] = []
                            for r in (body.get("results") or []):
                                r_status = (r.get("status") or "").lower()
                                if r_status in (
                                    "ok", "queued", "running", "dispatched"
                                ):
                                    kb_drained += 1
                                    dispatched += 1
                                    log.info(
                                        "[recon:%s] KB dispatched %s for %s → %s",
                                        eid[:8], r.get("scanner"),
                                        r.get("ip"),
                                        (r.get("job_id") or "?")[:8],
                                    )
                                    await self._emit_webhook(
                                        eid, "recon_agent_kb_dispatched",
                                        headers,
                                        {
                                            "engagement_id": eid,
                                            "rec_id": r.get("id"),
                                            "ip": r.get("ip"),
                                            "scanner": r.get("scanner"),
                                            "job_id": r.get("job_id"),
                                            "proxy": kb_proxy,
                                            "use_kali": use_kali,
                                            "node_id": kb_node_id,
                                            "source": "kb_recon",
                                        },
                                    )
                                elif r_status == "skipped":
                                    # Dispatcher decided this rec doesn't
                                    # warrant a fresh run (e.g. trivial nmap
                                    # NSE script already covered by service
                                    # detection, manual-only tool with no
                                    # kali/node, in-flight duplicate).  Mark
                                    # the rec status='skipped' in the DB so
                                    # the next cycle's queue scan doesn't
                                    # pick it back up and burn budget on the
                                    # same dead rec forever.
                                    rid = r.get("id")
                                    if rid:
                                        skipped_rec_ids.append(rid)
                                        log.info(
                                            "[recon:%s] KB rec skipped (%s) — marking 'skipped' in DB: %s",
                                            eid[:8], r.get("scanner"),
                                            (r.get("detail") or "")[:80],
                                        )
                                else:
                                    # Anything else is a FAILED dispatch, and it
                                    # used to fall through here silently: not
                                    # counted as drained, not marked skipped, not
                                    # logged. The cycle then reported
                                    # "dispatched=0" with no reason anywhere.
                                    #
                                    # Worse, it blocked the queue head. The fetch
                                    # is ORDER BY priority, created_at, so the same
                                    # failing recs came back first every cycle and
                                    # consumed the entire budget forever — 144 recs
                                    # pending, nothing moving, and the errors
                                    # (an AttributeError in the nmap branch, and a
                                    # tool missing from the Kali allowlist) never
                                    # reached the operator.
                                    #
                                    # 'failed' is already an existing status in this
                                    # table, so recording it here is consistent and
                                    # leaves the rec visible for re-queueing rather
                                    # than deleting it.
                                    #
                                    # But only PERMANENT failures are retired here.
                                    # "failed" covers both "Tool 'nc' is not in
                                    # allowed list" (a 400 that will never succeed)
                                    # and ConnectError/502 from a container that
                                    # happened to be restarting. Retiring both would
                                    # silently discard good recon work on a blip,
                                    # so transient failures stay pending and are
                                    # retried, bounded by MAX_DISPATCH_ATTEMPTS.
                                    rid = r.get("id")
                                    detail = r.get("detail") or ""
                                    permanent = _is_permanent_dispatch_failure(detail)
                                    kb_failed += 1
                                    log.warning(
                                        "[recon:%s] KB rec FAILED [%s] (%s for %s): %s",
                                        eid[:8],
                                        "permanent" if permanent else "transient",
                                        r.get("scanner"), r.get("ip"),
                                        (detail or "no detail")[:160],
                                    )
                                    if rid:
                                        if permanent:
                                            failed_rec_ids.append(rid)
                                        else:
                                            transient_rec_ids.append(rid)
                                    await self._emit_webhook(
                                        eid, "recon_agent_kb_dispatch_failed",
                                        headers,
                                        {
                                            "engagement_id": eid,
                                            "rec_id": rid,
                                            "ip": r.get("ip"),
                                            "scanner": r.get("scanner"),
                                            "detail": detail[:300],
                                            "failure_kind": (
                                                "permanent" if permanent
                                                else "transient"
                                            ),
                                        },
                                        severity="warning",
                                    )
                            # Bulk-update skipped rec IDs so they leave the
                            # pending queue.  One UPDATE per cycle keeps the
                            # txn small even if many recs were rejected.
                            # Transient failures: bump the attempt counter and
                            # leave the rec PENDING so it retries next cycle.
                            # Anything that has now burned MAX_DISPATCH_ATTEMPTS
                            # is retired regardless of classification — that is
                            # the backstop for a permanent failure whose detail
                            # string we did not recognise.
                            if transient_rec_ids:
                                try:
                                    with get_db() as conn, conn.cursor() as cur:
                                        cur.execute(
                                            """
                                            UPDATE scan_recommendations
                                               SET extra = jsonb_set(
                                                     COALESCE(extra, '{}'::jsonb),
                                                     '{dispatch_failures}',
                                                     to_jsonb(COALESCE(
                                                       (extra->>'dispatch_failures')::int, 0) + 1)
                                                   ),
                                                   updated_at = now()
                                             WHERE id = ANY(%s::uuid[])
                                         RETURNING id::text,
                                                   (extra->>'dispatch_failures')::int
                                            """,
                                            (transient_rec_ids,),
                                        )
                                        rows = cur.fetchall()
                                        conn.commit()
                                    for _rid, _n in rows:
                                        if _n and _n >= MAX_DISPATCH_ATTEMPTS:
                                            failed_rec_ids.append(_rid)
                                            log.warning(
                                                "[recon:%s] rec %s retired after %d "
                                                "failed attempts",
                                                eid[:8], _rid[:8], _n,
                                            )
                                except Exception as e:
                                    log.warning(
                                        "[recon:%s] failed to record %d transient "
                                        "failures: %s",
                                        eid[:8], len(transient_rec_ids), e,
                                    )
                            if failed_rec_ids:
                                try:
                                    with get_db() as conn, conn.cursor() as cur:
                                        cur.execute(
                                            "UPDATE scan_recommendations "
                                            "   SET status = 'failed', "
                                            "       updated_at = now() "
                                            " WHERE id = ANY(%s::uuid[])",
                                            (failed_rec_ids,),
                                        )
                                        conn.commit()
                                except Exception as e:
                                    log.warning(
                                        "[recon:%s] failed to mark %d recs as failed: %s",
                                        eid[:8], len(failed_rec_ids), e,
                                    )
                            if skipped_rec_ids:
                                try:
                                    with get_db() as conn, conn.cursor() as cur:
                                        cur.execute(
                                            "UPDATE scan_recommendations "
                                            "   SET status = 'skipped', "
                                            "       updated_at = now() "
                                            " WHERE id = ANY(%s::uuid[])",
                                            (skipped_rec_ids,),
                                        )
                                        conn.commit()
                                except Exception as e:
                                    log.warning(
                                        "[recon:%s] failed to mark %d recs as skipped: %s",
                                        eid[:8], len(skipped_rec_ids), e,
                                    )
                        else:
                            log.warning(
                                "[recon:%s] KB dispatch failed: %d %s",
                                eid[:8], resp.status_code, resp.text[:200],
                            )
                            await self._emit_webhook(
                                eid, "recon_agent_blocked", headers,
                                {
                                    "engagement_id": eid,
                                    "phase": "kb_drain",
                                    "reason": resp.text[:300],
                                    "status_code": resp.status_code,
                                },
                                severity="warning",
                            )
                    except Exception as e:
                        log.warning(
                            "[recon:%s] KB dispatch error: %s", eid[:8], e
                        )

            # Emit drained signal only when we actually moved recs AND no
            # backlog remains — operators / Slack get a clean "agent caught
            # up" ping rather than a noisy per-cycle heartbeat.
            if kb_drained > 0 and kb_skipped_pending == 0:
                await self._emit_webhook(
                    eid, "recon_agent_kb_queue_drained", headers,
                    {
                        "engagement_id": eid,
                        "drained": kb_drained,
                        "remaining_pending": 0,
                    },
                )

        # 5. Log to campaign events
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                await c.post(
                    f"{s.rag_api_url}/engagements/{eid}/campaign-events",
                    json={
                        "kill_chain_phase": "reconnaissance",
                        "title": f"Recon agent cycle: {dispatched} scans dispatched",
                        "description": (
                            f"Checked {len(open_followups)} open follow-ups, "
                            f"{len(targets)} scope targets, "
                            f"dispatched {dispatched} scans "
                            f"({kb_drained} from KB queue, "
                            f"{kb_skipped_pending} deferred this cycle, "
                            f"{kb_total_pending} still pending overall)"
                        ),
                        "operator": "recon_agent",
                        "detected": False,
                        "metadata": {
                            "dispatched": dispatched,
                            "kb_dispatched": kb_drained,
                            "kb_deferred_this_cycle": kb_skipped_pending,
                            "kb_pending_total": kb_total_pending,
                            "kb_driven_recon": kb_driven_recon,
                            "targets_checked": len(targets),
                            "followups_open": len(open_followups),
                            "profile": profile,
                        },
                    },
                    headers=headers,
                )
        except Exception:
            pass

        # 6. Update state
        now_iso = datetime.now(timezone.utc).isoformat()
        # last_dispatch_at is "when did this agent last dispatch anything", so it
        # has to survive cycles that dispatch nothing. Sending None on an idle
        # cycle PATCHed a null straight over the real timestamp, so the field only
        # ever reflected whether the MOST RECENT cycle happened to dispatch.
        #
        # That reads as "this agent has never dispatched" — which is exactly how
        # a healthy agent draining 1-2 recs every five minutes gets misdiagnosed
        # as stalled. Omit the key instead so the stored value stands.
        state_patch = {"last_run_at": now_iso, "last_scan_at": now_iso}
        if dispatched > 0:
            state_patch["last_dispatch_at"] = now_iso
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                await c.patch(
                    f"{s.rag_api_url}/recon-agent/{eid}",
                    json=state_patch,
                    headers=headers,
                )
        except Exception:
            pass

        # kb_drained belongs here. Without it the cycle reported "dispatched=0"
        # while the KB drain silently did nothing, and the two are separate
        # counters — so a queue that never moved looked identical to a healthy
        # cycle with no seed work to do.
        # Report the real backlog. kb_deferred is what THIS cycle looked at and
        # could not take; kb_pending_total is the whole queue for the engagement.
        log.info("[recon:%s] cycle done: dispatched=%d, kb_drained=%d, "
                 "kb_failed=%d, kb_deferred=%d, kb_pending_total=%d, "
                 "followups=%d, targets=%d",
                 eid[:8], dispatched, kb_drained, kb_failed, kb_skipped_pending,
                 kb_total_pending, len(open_followups), len(targets))

        # Webhook: cycle completed
        await self._emit_webhook(eid, "recon_agent_cycle_completed", headers, {
            "engagement_id": eid, "dispatched": dispatched,
            "followups_open": len(open_followups), "targets_checked": len(targets),
            "profile": profile,
        })


# Module-level singleton
_recon_agent: Optional[ReconAgent] = None


def get_agent() -> Optional[ReconAgent]:
    return _recon_agent


async def start_agent():
    global _recon_agent
    if _recon_agent is not None:
        return
    _recon_agent = ReconAgent()
    asyncio.create_task(_recon_agent.run())
    log.info("Recon agent background task started")


async def stop_agent():
    global _recon_agent
    if _recon_agent:
        _recon_agent.stop()
        _recon_agent = None
