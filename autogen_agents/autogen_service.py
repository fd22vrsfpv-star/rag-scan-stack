"""
Autogen Multi-Agent Service
FastAPI service for orchestrating AI agents in penetration testing
"""

import os
import re
import uuid
import httpx
import threading
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)
import logging

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

# Set up logger for retry attempts
retry_logger = logging.getLogger("autogen_service.retry")

# Set up session logger for pentest sessions (will be captured by log_manager)
session_logger = logging.getLogger("pentest_sessions")

from db_utils import (
    create_agent_session,
    update_agent_session,
    add_agent_message,
    get_agent_session,
    get_agent_messages,
    list_agent_sessions,
    delete_old_sessions,
    delete_agent_session,
    build_resume_context,
    get_db,
    ensure_schema,
)
from feedback_db import (
    create_feedback,
    update_feedback_rating,
    get_feedback,
    list_feedback,
    get_feedback_stats,
    export_training_dataset,
    capture_session_outputs,
)
from log_manager import get_log_handler, setup_log_capture
from exploit_watcher import get_exploit_watcher, start_exploit_watcher
from scan_tools import scan_tracker, get_session_scan_status
from llm_metrics import LLMMetricsContext
from report_generator import (
    db_get_report_summary,
    db_get_vulnerabilities_by_severity,
    db_get_vulnerability_detail,
    db_get_tool_results,
    get_exploit_links,
    generate_full_report,
    generate_pentester_markdown_report,
    generate_pentester_text_report,
    SEVERITY_LEVELS
)


# ===============================
# Session Watchdog Configuration
# ===============================
SESSION_WATCHDOG_ENABLED = os.environ.get("SESSION_WATCHDOG_ENABLED", "true").lower() == "true"
SESSION_STALL_TIMEOUT = int(os.environ.get("SESSION_STALL_TIMEOUT", "3600"))  # 1 hour default - blocking scans can take a long time
SESSION_WATCHDOG_INTERVAL = int(os.environ.get("SESSION_WATCHDOG_INTERVAL", "30"))  # Check every 30s

# Auto-recovery configuration
SESSION_AUTO_RECOVERY_ENABLED = os.environ.get("SESSION_AUTO_RECOVERY_ENABLED", "true").lower() == "true"
SESSION_MAX_RECOVERY_ATTEMPTS = int(os.environ.get("SESSION_MAX_RECOVERY_ATTEMPTS", "3"))  # Max recovery tries

# Dynamic timeout configuration
MIN_SESSION_TIMEOUT = int(os.environ.get("MIN_SESSION_TIMEOUT", "300"))  # 5 minutes minimum
MAX_SESSION_TIMEOUT = int(os.environ.get("MAX_SESSION_TIMEOUT", "28800"))  # 8 hours maximum
TIMEOUT_PER_ASSET = int(os.environ.get("TIMEOUT_PER_ASSET", "45"))  # 45 seconds per asset


def calculate_dynamic_session_timeout(session_config: Dict[str, Any]) -> int:
    """
    Calculate dynamic session timeout based on scan scope and complexity.

    Args:
        session_config: Session configuration containing targets and scan types

    Returns:
        Calculated timeout in seconds
    """
    try:
        # Base timeout (5 minutes minimum)
        base_timeout = MIN_SESSION_TIMEOUT

        # Asset-based scaling
        targets = session_config.get('targets', [])
        if isinstance(targets, str):
            targets = [targets]  # Handle single target as string
        asset_count = len(targets) if targets else 1
        asset_timeout = asset_count * TIMEOUT_PER_ASSET

        # Scan type multipliers based on expected duration
        scan_types = session_config.get('scan_types', [])
        if isinstance(scan_types, str):
            scan_types = [scan_types]

        type_multipliers = {
            'port_scan': 1.0,      # Basic port scanning
            'masscan': 1.2,        # Fast port scanning
            'nmap': 2.0,           # Detailed service detection
            'vuln_scan': 2.5,      # Vulnerability scanning
            'nuclei': 2.5,         # Template-based scanning
            'web_scan': 3.0,       # Web application scanning
            'zap': 3.5,            # ZAP proxy scanning
            'playwright': 3.0,     # Browser-based scanning
            'exploit_test': 4.0,   # Exploit execution
            'brute_force': 5.0,    # Credential attacks
            'manual': 1.5          # Manual testing
        }

        # Get maximum multiplier from scan types
        type_multiplier = 1.0
        for scan_type in scan_types:
            multiplier = type_multipliers.get(scan_type.lower(), 1.0)
            type_multiplier = max(type_multiplier, multiplier)

        # Calculate total timeout
        calculated_timeout = int((base_timeout + asset_timeout) * type_multiplier)

        # Apply limits
        final_timeout = min(max(calculated_timeout, MIN_SESSION_TIMEOUT), MAX_SESSION_TIMEOUT)

        session_logger.info(
            f"Dynamic timeout calculated: {final_timeout}s "
            f"(base: {base_timeout}s, assets: {asset_count}×{TIMEOUT_PER_ASSET}s, "
            f"multiplier: {type_multiplier:.1f}x, range: {MIN_SESSION_TIMEOUT}-{MAX_SESSION_TIMEOUT}s)"
        )

        return final_timeout

    except Exception as e:
        session_logger.warning(f"Error calculating dynamic timeout: {e}, using default {SESSION_STALL_TIMEOUT}s")
        return SESSION_STALL_TIMEOUT


def get_session_timeout(session_id: str) -> int:
    """
    Get the appropriate timeout for a session.

    Args:
        session_id: Session UUID as string

    Returns:
        Timeout in seconds
    """
    try:
        # Get session from database
        session = get_agent_session(uuid.UUID(session_id))
        if not session:
            return SESSION_STALL_TIMEOUT

        # Use dynamic timeout if configuration is available
        config = session.get('configuration', {})
        if config:
            return calculate_dynamic_session_timeout(config)

        # Fallback to fixed timeout
        return SESSION_STALL_TIMEOUT

    except Exception as e:
        session_logger.warning(f"Error getting session timeout: {e}, using default")
        return SESSION_STALL_TIMEOUT

# Exploit Watcher Configuration
EXPLOIT_WATCHER_ENABLED = os.environ.get("EXPLOIT_WATCHER_ENABLED", "true").lower() == "true"

# Track last activity per session
session_last_activity: Dict[str, datetime] = {}
session_last_message_count: Dict[str, int] = {}
session_recovery_attempts: Dict[str, int] = {}  # Track recovery attempts per session
session_heartbeats: Dict[str, datetime] = {}  # Heartbeats from blocking tools (e.g. wait_for_job_completion)

# Track scan jobs for stuck job detection
scan_job_tracking: Dict[str, Dict[str, Any]] = {}  # job_id -> {service_url, last_check, start_time, stage}
scan_job_recovery_attempts: Dict[str, int] = {}  # Track recovery attempts per job

watchdog_logger = logging.getLogger("session_watchdog")

# Webhook-driven job completion: job_id → {"event": threading.Event, "result": dict|None}
_job_events: Dict[str, Dict] = {}
_job_events_lock = threading.Lock()
webhook_logger = logging.getLogger("autogen_service.webhooks")


def register_job_wait(job_id: str) -> threading.Event:
    """Register a threading.Event for a job so the webhook handler can wake us up."""
    with _job_events_lock:
        if job_id in _job_events:
            return _job_events[job_id]["event"]
        evt = threading.Event()
        _job_events[job_id] = {"event": evt, "result": None}
        return evt


def get_job_event_result(job_id: str) -> Optional[dict]:
    """Retrieve the webhook payload stored for a completed job."""
    with _job_events_lock:
        entry = _job_events.get(job_id)
        return entry["result"] if entry else None


def cleanup_job_wait(job_id: str):
    """Remove job event entry after we're done waiting."""
    with _job_events_lock:
        _job_events.pop(job_id, None)


# Health check utilities
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
    before_sleep=before_sleep_log(retry_logger, logging.WARNING),
    reraise=True
)
async def check_ollama_health_with_retry(timeout: int = 5) -> tuple[bool, str]:
    """
    Check Ollama health with retry logic (internal function)

    Args:
        timeout: Request timeout in seconds

    Returns:
        Tuple of (is_healthy, message)

    Raises:
        httpx.ConnectError: If connection fails after retries
        httpx.TimeoutException: If timeout occurs after retries
    """
    ollama_url = os.environ.get("OLLAMA_URL", "http://ollama:11434")

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Check if Ollama is responsive
        response = await client.get(f"{ollama_url}/api/tags")

        if response.status_code != 200:
            return False, f"Ollama returned status {response.status_code}"

        # Check if models are available
        data = response.json()
        models = data.get("models", [])

        if not models:
            return False, "No models available in Ollama"

        return True, f"Ollama healthy with {len(models)} model(s) available"


async def check_ollama_health(timeout: int = 5, with_retry: bool = False) -> tuple[bool, str]:
    """
    Check if Ollama service is accessible and has models available

    Args:
        timeout: Request timeout in seconds
        with_retry: Enable retry logic (3 attempts with exponential backoff)

    Returns:
        Tuple of (is_healthy, message)
    """
    ollama_url = os.environ.get("OLLAMA_URL", "http://ollama:11434")

    try:
        if with_retry:
            return await check_ollama_health_with_retry(timeout)
        else:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(f"{ollama_url}/api/tags")

                if response.status_code != 200:
                    return False, f"Ollama returned status {response.status_code}"

                data = response.json()
                models = data.get("models", [])

                if not models:
                    return False, "No models available in Ollama"

                return True, f"Ollama healthy with {len(models)} model(s) available"

    except httpx.ConnectError as e:
        return False, f"Cannot connect to Ollama at {ollama_url}. Service may be down or unreachable."
    except httpx.TimeoutException:
        return False, f"Ollama connection timeout after {timeout}s"
    except Exception as e:
        return False, f"Ollama health check failed: {type(e).__name__}: {str(e)}"


async def check_azure_health(timeout: int = 5) -> tuple[bool, str]:
    """
    Check Azure LLM endpoint health by sending a minimal chat completions request.

    Returns:
        Tuple of (is_healthy, message)
    """
    endpoint = os.environ.get("AZURE_ENDPOINT", "")
    api_key = os.environ.get("AZURE_API_KEY", "")
    model = os.environ.get("AZURE_MODEL", "gpt-4o")
    api_version = os.environ.get("AZURE_API_VERSION", "2024-08-01-preview")

    if not endpoint or not api_key:
        return False, "Azure endpoint or API key not configured"

    base = endpoint.rstrip("/")
    if ".models.ai.azure.com" in base:
        url = f"{base}/v1/chat/completions"
    else:
        url = f"{base}/openai/deployments/{model}/chat/completions?api-version={api_version}"

    headers = {"api-key": api_key, "Content-Type": "application/json"}
    payload = {"messages": [{"role": "user", "content": "ping"}], "max_tokens": 1}

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                return True, f"Azure ({model}) healthy"
            else:
                return False, f"Azure returned status {response.status_code}"
    except httpx.ConnectError:
        return False, f"Cannot connect to Azure at {endpoint}"
    except httpx.TimeoutException:
        return False, f"Azure connection timeout after {timeout}s"
    except Exception as e:
        return False, f"Azure health check failed: {type(e).__name__}: {str(e)}"


def resolved_llm_probe() -> "tuple[str, dict, dict] | None":
    """(url, headers, payload) for a minimal chat completion against the ACTIVE
    backend, or None if the resolved config is unusable.

    `get_llm_config()` reads the dashboard DB first and env second. The env-only
    checks (`check_azure_health` / `check_ollama_health`) therefore answer a
    different question than the one that matters: here `get_llm_backend()` says
    "azure" from the DB while AZURE_ENDPOINT and AZURE_API_KEY are both EMPTY,
    so those checks reported "Azure endpoint or API key not configured" for a
    backend that works perfectly. That disabled the whole session pre-flight,
    and left /health advertising ok=false indefinitely.
    """
    try:
        from agent_config import get_llm_config
        cfg = (get_llm_config() or [{}])[0]
    except Exception:
        return None
    base_url = (cfg.get("base_url") or "").rstrip("/")
    model = cfg.get("model") or ""
    if not base_url or not model:
        return None
    api_key = cfg.get("api_key") or ""
    if (cfg.get("api_type") or "openai").lower() == "azure" and cfg.get("api_version"):
        url = f"{base_url}/openai/deployments/{model}/chat/completions?api-version={cfg['api_version']}"
        headers = {"api-key": api_key, "Content-Type": "application/json"}
    else:
        # OpenAI-compatible (incl. Azure AI Services /openai/v1 and Ollama /v1):
        # the model goes in the body, not the path.
        url = f"{base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    return url, headers, {"model": model, "max_tokens": 1,
                          "messages": [{"role": "user", "content": "ping"}]}


def interpret_llm_probe(status_code: int, body: str, model_hint: str = "") -> tuple[bool, str]:
    """Shared verdict for a probe response.

    A 429 counts as HEALTHY: rate-limited means reachable and authorised, and
    refusing to start a session does strictly less than starting one and letting
    its own retries and per-phase fallbacks handle the throttle.
    """
    if status_code == 200:
        return True, f"{model_hint} healthy".strip()
    if status_code == 429:
        return True, f"{model_hint} reachable but rate limited (429)".strip()
    return False, f"{model_hint} returned status {status_code}: {body[:160]}".strip()


async def check_resolved_llm_health(timeout: int = 5) -> "tuple[bool, str] | None":
    """Async probe of the resolved backend. None => nothing usable resolved, so
    the caller should fall back to the env-var checks rather than guess."""
    target = resolved_llm_probe()
    if target is None:
        return None
    url, headers, payload = target
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.post(url, json=payload, headers=headers)
        return interpret_llm_probe(r.status_code, r.text, payload["model"])
    except Exception as e:  # noqa: BLE001
        return False, f"{payload['model']} unreachable: {type(e).__name__}: {e}"


async def check_llm_health(timeout: int = 5, with_retry: bool = False) -> tuple[bool, str]:
    """
    Check LLM health based on configured backend (ollama, vllm, or azure).

    Returns:
        Tuple of (is_healthy, message)
    """
    from agent_config import get_llm_backend
    backend = get_llm_backend()

    # Check what the agents ACTUALLY use before falling back to the env-only
    # checks below. See resolved_llm_probe() for why this order matters.
    resolved = await check_resolved_llm_health(timeout)
    if resolved is not None:
        return resolved

    if backend == "azure":
        return await check_azure_health(timeout)
    else:
        return await check_ollama_health(timeout, with_retry=with_retry)


async def check_service_health(service_name: str, url: str, timeout: int = 3) -> tuple[bool, str]:
    """
    Generic health check for scanner services

    Args:
        service_name: Name of the service
        url: Health check URL
        timeout: Request timeout in seconds

    Returns:
        Tuple of (is_healthy, message)
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            response = await client.get(url)

            if response.status_code == 200:
                return True, f"{service_name} is healthy"
            else:
                return False, f"{service_name} returned status {response.status_code}"

    except httpx.ConnectError:
        return False, f"Cannot connect to {service_name} at {url}"
    except httpx.TimeoutException:
        return False, f"{service_name} timeout after {timeout}s"
    except Exception as e:
        return False, f"{service_name} check failed: {str(e)}"


# LLM metrics used to be captured here by monkeypatching AutoGen's
# OpenAIWrapper.create. With AutoGen retired there is nothing to patch: the
# LangGraph engine writes the same llm_request_metrics rows through a LangChain
# callback (langgraph_engine.metrics_callback), so the table and every dashboard
# that reads it are unchanged.

# FastAPI app
app = FastAPI(
    title="Autogen Multi-Agent Pentest Service",
    description="AI-powered penetration testing orchestration with specialized agents",
    version="1.0.0"
)


# Pydantic models
class PentestRequest(BaseModel):
    target_description: str = Field(
        ..., description="Description of the target (e.g., '192.168.1.0/24 web application')"
    )
    session_name: str = Field(..., description="Human-readable name for this pentest session")
    initial_task: str = Field(
        ..., description="Initial task for the agents (e.g., 'Perform reconnaissance and identify vulnerabilities')"
    )
    max_rounds: Optional[int] = Field(200, description="Maximum conversation rounds (status polls don't count)")
    auto_execute_scans: Optional[bool] = Field(True, description="Automatically execute recommended scans")
    enable_recon_agent: Optional[bool] = Field(
        None,
        description=(
            "Enable the continuous recon agent for this session's engagement at "
            "launch (X-Engagement-Id). It drains the KB recommendation queue every "
            "cycle. Defaults to the ENABLE_RECON_AGENT_ON_LAUNCH env var."
        ),
    )
    recon_agent_interval_sec: Optional[int] = Field(
        300, description="Recon agent cycle interval when enable_recon_agent is set."
    )
    auto_run_recommendations: Optional[bool] = Field(
        None,
        description=(
            "When the session ends, dispatch the KB scan recommendations it "
            "generated but never acted on. The post-ingest recommender writes "
            "scan_recommendations per discovered (ip, service); without this they "
            "sit at status='pending' indefinitely. Defaults to the "
            "AUTO_RUN_RECOMMENDATIONS env var (off unless set)."
        ),
    )
    proxy: Optional[str] = Field(None, description="SOCKS proxy URL for routing scans through a remote node (e.g., 'socks5://node-manager:10001')")
    port_profile: Optional[str] = Field(None, description="Named port scope from knowledge/port_profiles.yaml (top-100, top-1000, web, redteam-targeted, all). Omit to use the scanner agent's built-in quick-then-deep policy.")
    web_profile: Optional[str] = Field(None, description="Named web scan depth from knowledge/web_profiles.yaml (quick, standard, deep, api, passive-web). Omit to use each web tool's own defaults.")
    engine: Optional[str] = Field(
        None,
        description=(
            "Orchestration engine for THIS session: 'langgraph' (default) or "
            "'autogen' (the legacy GroupChat, kept as a fallback for one release "
            "per Docs/LANGGRAPH_MIGRATION_PLAN.md). Omit to use the AGENT_ENGINE "
            "env default. This is the canary control: an operator can pin a "
            "single session to either engine without restarting the service."
        ),
    )
    enable_exploit_phase: Optional[bool] = Field(
        None,
        description=(
            "LangGraph engine only. Adds the exploit phase after analysis: the "
            "agent queues ONE best-evidenced candidate for approval, then the "
            "graph PAUSES on a durable interrupt until the operator answers "
            "POST /pentest/{id}/approve. Off unless set (LANGGRAPH_EXPLOIT_PHASE "
            "env default) — a session with it on will sit at "
            "status='awaiting_approval' until a human acts."
        ),
    )
    enable_surface_test_phase: Optional[bool] = Field(
        None,
        description=(
            "LangGraph engine only. Adds the attack-surface test phase after "
            "analysis: the agent enumerates ONE target's surface, generates "
            "custom security tests, runs the SAFE ones autonomously (recorded "
            "with pass/fail history) and PAUSES on the same durable interrupt "
            "for any IMPACTFUL test until the operator answers "
            "POST /pentest/{id}/approve. Off unless set "
            "(LANGGRAPH_SURFACE_TEST_PHASE env default)."
        ),
    )
    surface_target_host: Optional[str] = Field(
        None,
        description=(
            "Surface-test phase only. The ONE host/IP to enumerate and prove "
            "exhaustively. Omit to let the agent pick the highest-risk host "
            "from get_attack_vectors. Must be in scope — the scope gate still "
            "refuses out-of-scope dispatch."
        ),
    )
    enable_test_synthesis: Optional[bool] = Field(
        None,
        description=(
            "Surface-test phase only. Instead of the fixed WSTG-map command, the "
            "LLM AUTHORS a custom test per web finding (bounded; falls back to the "
            "map on any failure). Synthesized tests are fail-safe classified and "
            "impactful ones still require approval. Off unless set "
            "(LANGGRAPH_SYNTH_TESTS env default)."
        ),
    )


class ApprovalRequest(BaseModel):
    """The operator's answer to a paused LangGraph approval interrupt."""
    approved: bool = Field(..., description="True to execute the queued exploit, False to decline and go to the report.")
    pending_exploit_id: Optional[str] = Field(
        None,
        description=(
            "The pending_exploits row to execute. REQUIRED when approved=true — "
            "without it there is nothing to execute and the graph records the "
            "approval as a no-op rather than guessing which exploit was meant."
        ),
    )
    note: Optional[str] = Field(None, description="Operator note recorded on the session timeline.")


class ResumeRequest(BaseModel):
    max_rounds: Optional[int] = Field(200, description="Maximum conversation rounds")
    additional_instructions: Optional[str] = Field(None, description="Extra instructions for the resumed session")
    proxy: Optional[str] = Field(None, description="SOCKS proxy URL — switch or keep proxy for resumed session")


class PentestResponse(BaseModel):
    session_id: str
    status: str
    message: str


class SessionStatus(BaseModel):
    session_id: str
    session_name: str
    status: str
    target_description: str
    started_at: str
    ended_at: Optional[str]
    message_count: int
    summary: Optional[str]


class AgentMessage(BaseModel):
    agent_name: str
    role: str
    content: str
    timestamp: str


# --- Report Models ---

class ToolExecutionSummary(BaseModel):
    """Summary of tool executions."""
    tool: str
    executions: int
    successful: int
    failed: int
    avg_duration: float
    findings: List[str] = []  # Key findings from this tool


class PortSummary(BaseModel):
    """Summary of discovered port."""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    findings_count: int


class ScanPeriod(BaseModel):
    """Time period of scan."""
    started: Optional[str] = None
    ended: Optional[str] = None


class ReportSummaryResponse(BaseModel):
    """Response for report summary endpoint."""
    target: Optional[str] = None
    scan_period: ScanPeriod
    tools_summary: List[ToolExecutionSummary]
    ports_discovered: List[PortSummary]
    findings_by_severity: Dict[str, int]


class VulnerabilityEntry(BaseModel):
    """Single vulnerability entry in list."""
    id: str
    title: str
    tool: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    cve: List[str] = []
    detail_url: str


class VulnerabilitiesResponse(BaseModel):
    """Response for vulnerabilities list endpoint."""
    target: Optional[str] = None
    vulnerabilities: Dict[str, List[VulnerabilityEntry]]


class ToolResult(BaseModel):
    """Detailed result from a single tool execution."""
    id: str
    tool: str
    command: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    severity: str
    cves: List[str] = []
    findings: List[str]  # Key findings as bullet points
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration: float
    status: str = "completed"  # execution status (completed/failed/timeout)
    exit_code: Optional[int] = None
    raw_output: Optional[str] = None  # only when requested
    error_output: Optional[str] = None  # stderr if any


class ToolResultsResponse(BaseModel):
    """Response for tool results endpoint."""
    target: Optional[str] = None
    results: List[ToolResult]
    total: int


class ExploitLink(BaseModel):
    """Link to exploit information."""
    name: str
    type: str  # metasploit, exploitdb, github, reference, tool
    source: Optional[str] = None
    module: Optional[str] = None
    url: Optional[str] = None
    edb_id: Optional[str] = None
    description: Optional[str] = None


class VulnerabilityDetailResponse(BaseModel):
    """Full detail for one vulnerability."""
    id: str
    severity: str
    title: str
    tool: str
    command: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    raw_output: str
    error_output: Optional[str] = None
    parsed_results: Dict[str, Any]
    cve: List[str] = []
    exploit_links: List[ExploitLink] = []
    reproduction_steps: List[str] = []
    reproduction_command: str
    remediation: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class FullReportResponse(BaseModel):
    """Full report response."""
    target: str
    generated_at: str
    format: str
    summary: ReportSummaryResponse
    vulnerabilities: Dict[str, List[VulnerabilityEntry]]
    rendered: Optional[str] = None  # For HTML/markdown formats


# Global session storage for active sessions
active_sessions: Dict[str, Dict] = {}


# ===============================
# Session Recovery — REMOVED
# ===============================
# `attempt_session_recovery()` lived here. It recovered a stalled session by
# appending a nudge message to `groupchat.messages` and hoping AutoGen's speaker
# selection picked it up. There is no speaker-selection loop in a StateGraph, so
# there is nothing to nudge — and the deterministic edges remove the stall class
# the recovery existed for. Retired with AutoGen
# (Docs/LANGGRAPH_MIGRATION_PLAN.md, Phase 5). The watchdog still DETECTS a
# stalled session and labels it; it no longer pretends it can revive one.

# ===============================
# Session Watchdog
# ===============================

async def session_watchdog():
    """
    Enhanced AI Agent Watchdog - monitors both AI sessions and scan jobs.

    AI Sessions: Detects when a session hasn't made progress (no new messages)
    for SESSION_STALL_TIMEOUT seconds and marks it as stalled.

    Scan Jobs: Monitors individual scanner jobs for stuck states, detects jobs
    that are hung in specific stages, and attempts intelligent recovery.
    """
    import asyncio

    watchdog_logger.info(f"Enhanced AI Watchdog started - monitoring sessions AND scan jobs (session timeouts: {MIN_SESSION_TIMEOUT}-{MAX_SESSION_TIMEOUT}s, interval={SESSION_WATCHDOG_INTERVAL}s)")

    while True:
        try:
            await asyncio.sleep(SESSION_WATCHDOG_INTERVAL)

            # Get all active sessions
            sessions = list_agent_sessions(status="active", limit=100)

            now = datetime.utcnow()

            for session in sessions:
                session_id = str(session['id'])
                session_name = session['session_name']

                # Get current message count
                messages = get_agent_messages(uuid.UUID(session_id), limit=1000)
                current_count = len(messages)

                # Check if this session is in our tracking
                if session_id not in session_last_activity:
                    # First time seeing this session, initialize tracking
                    session_last_activity[session_id] = now
                    session_last_message_count[session_id] = current_count
                    watchdog_logger.debug(f"[{session_id[:8]}] Tracking new session: {session_name} ({current_count} messages)")
                    continue

                last_count = session_last_message_count.get(session_id, 0)
                last_activity = session_last_activity.get(session_id, now)

                # Check if there's been progress (new messages)
                if current_count > last_count:
                    # Session is making progress
                    session_last_activity[session_id] = now
                    session_last_message_count[session_id] = current_count
                    watchdog_logger.debug(f"[{session_id[:8]}] Progress: {last_count} -> {current_count} messages")
                else:
                    # No progress - check how long it's been stalled
                    stall_time = (now - last_activity).total_seconds()

                    # Check if a blocking tool (e.g. wait_for_job_completion) sent a heartbeat
                    heartbeat_str = scan_tracker.get_last_heartbeat(session_id)
                    if heartbeat_str:
                        try:
                            heartbeat_dt = datetime.fromisoformat(heartbeat_str.replace("Z", "+00:00")).replace(tzinfo=None)
                            heartbeat_age = (now - heartbeat_dt).total_seconds()
                            if heartbeat_age < SESSION_STALL_TIMEOUT:
                                # Blocking tool is still active - not stalled
                                watchdog_logger.debug(
                                    f"[{session_id[:8]}] Blocking tool heartbeat {heartbeat_age:.0f}s ago - not stalled"
                                )
                                continue
                        except (ValueError, TypeError):
                            pass  # Invalid heartbeat timestamp, proceed with stall check

                    # Get dynamic timeout for this session
                    session_timeout = get_session_timeout(session_id)

                    if stall_time >= session_timeout:
                        # Session has stalled!
                        recovery_attempts = session_recovery_attempts.get(session_id, 0)

                        # Stall DETECTION is still worth having: a session whose
                        # LLM call never returns makes no progress and should be
                        # labelled rather than left looking active.
                        #
                        # Stall RECOVERY is gone with AutoGen. It worked by
                        # appending a nudge message to `groupchat.messages` and
                        # hoping the speaker-selection loop picked it up — there
                        # is no such loop to nudge in a StateGraph, and the
                        # deterministic edges remove the failure mode the
                        # recovery existed for. See
                        # Docs/LANGGRAPH_MIGRATION_PLAN.md §5.1.
                        watchdog_logger.warning(
                            f"[{session_id[:8]}] SESSION STALLED - no progress for "
                            f"{stall_time:.0f}s, messages: {current_count}. Marking stalled."
                        )
                        try:
                            update_agent_session(
                                session_id=uuid.UUID(session_id),
                                status="stalled",
                                summary=f"Session stalled - no progress for {stall_time:.0f} seconds. "
                                       f"Last message count: {current_count}. "
                                       f"Resume it to continue from where it stopped."
                            )

                            # Remove from active_sessions dict
                            if session_id in active_sessions:
                                del active_sessions[session_id]

                            # Clean up tracking
                            if session_id in session_last_activity:
                                del session_last_activity[session_id]
                            if session_id in session_last_message_count:
                                del session_last_message_count[session_id]
                            if session_id in session_recovery_attempts:
                                del session_recovery_attempts[session_id]
                            if session_id in session_heartbeats:
                                del session_heartbeats[session_id]

                            watchdog_logger.info(f"[{session_id[:8]}] Session marked as stalled and cleaned up")

                        except Exception as e:
                            watchdog_logger.error(f"[{session_id[:8]}] Failed to mark session as stalled: {e}")

                    elif stall_time >= session_timeout / 2:
                        # Session is approaching stall threshold - log warning
                        watchdog_logger.warning(
                            f"[{session_id[:8]}] Session approaching stall: "
                            f"No progress for {stall_time:.0f}s (dynamic threshold: {session_timeout}s)"
                        )

            # Clean up tracking for sessions that are no longer active
            active_ids = {str(s['id']) for s in sessions}
            stale_ids = set(session_last_activity.keys()) - active_ids
            for stale_id in stale_ids:
                if stale_id in session_last_activity:
                    del session_last_activity[stale_id]
                if stale_id in session_last_message_count:
                    del session_last_message_count[stale_id]
                if stale_id in session_heartbeats:
                    del session_heartbeats[stale_id]

            # ===============================
            # Scan Job Monitoring
            # ===============================
            await monitor_stuck_scan_jobs(now)

        except Exception as e:
            watchdog_logger.error(f"Watchdog error: {e}")
            import traceback
            watchdog_logger.error(traceback.format_exc())


async def monitor_stuck_scan_jobs(now: datetime):
    """
    Monitor individual scan jobs for stuck/stalled states.

    This extends the AI agent watchdog to also monitor standalone scan jobs
    that aren't part of AI agent sessions.
    """
    try:
        import httpx

        # Scanner services to monitor
        scanner_services = [
            ("https://nmap_scanner:8012", "nmap"),
            ("https://web-scanner:8010", "web"),
            ("https://nuclei-runner:8020", "nuclei"),
            ("https://pd-runner:8023", "pd"),
            ("https://osint-runner:8024", "osint"),
            ("https://brutus-runner:8026", "brutus"),
            ("https://playwright-scanner:8025", "playwright"),
        ]

        api_key = os.environ.get("API_KEY", "changeme")
        headers = {"x-api-key": api_key}

        # Check each scanner service for running jobs
        for service_url, service_name in scanner_services:
            try:
                async with httpx.AsyncClient(verify=False, timeout=5) as client:
                    # Get active/running jobs from this service
                    response = await client.get(f"{service_url}/jobs", headers=headers)

                    if response.status_code == 200:
                        jobs = response.json()
                        running_jobs = [job for job in jobs if job.get("status") == "running"]

                        for job in running_jobs:
                            job_id = job.get("id") or job.get("job_id")
                            if not job_id:
                                continue

                            await check_job_for_stuck_state(service_url, service_name, job_id, job, now, headers)

            except Exception as e:
                watchdog_logger.debug(f"[scan-monitor] Failed to check {service_name} service: {e}")

        # Cleanup tracking for jobs that are no longer running
        await cleanup_completed_job_tracking()

    except Exception as e:
        watchdog_logger.error(f"[scan-monitor] Error monitoring scan jobs: {e}")


async def check_job_for_stuck_state(service_url: str, service_name: str, job_id: str, job: dict, now: datetime, headers: dict):
    """Check if a specific job is stuck and handle recovery."""
    try:
        import httpx

        # Get detailed job status
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            job_response = await client.get(f"{service_url}/jobs/{job_id}", headers=headers)

            if job_response.status_code != 200:
                return

            job_detail = job_response.json()
            current_stage = job_detail.get("stage", "unknown")
            job_status = job_detail.get("status", "unknown")

            # Skip if job is no longer running
            if job_status != "running":
                if job_id in scan_job_tracking:
                    del scan_job_tracking[job_id]
                return

            # Initialize tracking for new jobs
            if job_id not in scan_job_tracking:
                scan_job_tracking[job_id] = {
                    "service_url": service_url,
                    "service_name": service_name,
                    "start_time": now,
                    "last_check": now,
                    "last_stage": current_stage,
                    "stage_start_time": now,
                }
                watchdog_logger.debug(f"[scan-monitor] Tracking new {service_name} job: {job_id[:8]}")
                return

            job_info = scan_job_tracking[job_id]
            last_stage = job_info.get("last_stage")
            stage_start_time = job_info.get("stage_start_time", now)
            job_start_time = job_info.get("start_time", now)

            # Check if stage has changed (progress indicator)
            if current_stage != last_stage:
                # Job made progress
                job_info["last_stage"] = current_stage
                job_info["stage_start_time"] = now
                job_info["last_check"] = now
                watchdog_logger.debug(f"[scan-monitor] {service_name} job {job_id[:8]} progressed: {last_stage} -> {current_stage}")
                return

            # Check for stuck conditions
            stage_duration = (now - stage_start_time).total_seconds()
            total_duration = (now - job_start_time).total_seconds()

            # Define timeouts based on job type, stage, and scan scope
            stage_timeout = get_job_stage_timeout(service_name, current_stage, job_detail)
            total_timeout = get_job_total_timeout(service_name, job_detail)

            is_stuck = False
            stuck_reason = ""

            if stage_duration > stage_timeout:
                is_stuck = True
                stuck_reason = f"stuck in stage '{current_stage}' for {stage_duration:.0f}s (limit: {stage_timeout}s)"
            elif total_duration > total_timeout:
                is_stuck = True
                stuck_reason = f"total runtime {total_duration:.0f}s exceeds limit ({total_timeout}s)"

            if is_stuck:
                recovery_attempts = scan_job_recovery_attempts.get(job_id, 0)

                if recovery_attempts < 2:  # Allow 2 recovery attempts
                    watchdog_logger.warning(f"[scan-monitor] {service_name} job {job_id[:8]} {stuck_reason} - attempting recovery")

                    success = await recover_stuck_scan_job(service_url, service_name, job_id, headers)
                    scan_job_recovery_attempts[job_id] = recovery_attempts + 1

                    if success:
                        watchdog_logger.info(f"[scan-monitor] Successfully recovered {service_name} job {job_id[:8]}")
                    else:
                        watchdog_logger.warning(f"[scan-monitor] Recovery attempt failed for {service_name} job {job_id[:8]}")
                else:
                    watchdog_logger.error(f"[scan-monitor] {service_name} job {job_id[:8]} {stuck_reason} - max recovery attempts reached, marking as failed")

                    # Force mark as failed
                    await mark_scan_job_failed(service_url, service_name, job_id, stuck_reason, headers)

                    # Cleanup tracking
                    if job_id in scan_job_tracking:
                        del scan_job_tracking[job_id]
                    if job_id in scan_job_recovery_attempts:
                        del scan_job_recovery_attempts[job_id]

            # Update last check time
            job_info["last_check"] = now

    except Exception as e:
        watchdog_logger.error(f"[scan-monitor] Error checking job {job_id[:8] if job_id else 'unknown'}: {e}")


def get_job_stage_timeout(service_name: str, stage: str, job_detail: dict = None) -> int:
    """Get timeout for a specific job stage - scales dynamically based on scan scope."""
    # Base stage-specific timeouts (for single host)
    base_timeouts = {
        "masscan": 600,   # 10 minutes base for port scanning
        "nmap_service_detection": 1800,  # 30 minutes base for service detection
        "ingest_masscan": 300,  # 5 minutes base for database ingestion
        "ingest_nmap": 300,     # 5 minutes base for ingestion
        "nuclei_scan": 1800,    # 30 minutes base for vulnerability scanning
        "web_scan": 1200,       # 20 minutes base for web scanning
        "gobuster": 900,        # 15 minutes base for directory enumeration
        "playwright_scan": 1200, # 20 minutes base for browser automation
        "full_scan": 3600,      # 1 hour base for comprehensive scans
        "deep_scan": 5400,      # 1.5 hours base for deep scanning
    }

    base_timeout = base_timeouts.get(stage, 1800)  # Default 30 minutes base

    # Extract host count from job details
    host_count = 1  # Default single host
    if job_detail:
        try:
            # Try various ways to extract host count
            targets = job_detail.get("targets", [])
            command = job_detail.get("command", "")

            if isinstance(targets, list):
                host_count = len(targets)
            elif isinstance(targets, str):
                # Count comma-separated or space-separated targets
                host_count = len([t.strip() for t in targets.replace(" ", ",").split(",") if t.strip()])
            elif "target" in job_detail:
                target = job_detail["target"]
                if isinstance(target, str):
                    # Check for CIDR notation or multiple IPs
                    if "/" in target:
                        # CIDR notation - estimate host count
                        try:
                            import ipaddress
                            network = ipaddress.IPv4Network(target, strict=False)
                            host_count = min(network.num_addresses, 1000)  # Cap at 1000 for timeout calc
                        except:
                            host_count = 1
                    else:
                        host_count = len([t.strip() for t in target.replace(" ", ",").split(",") if t.strip()])

            # Parse command line for host indicators
            if host_count == 1 and command:
                if " -iL " in command or " --hostfile " in command:
                    # Host file referenced - assume larger scope
                    host_count = 50
                elif any(cidr in command for cidr in ["/24", "/16", "/8"]):
                    # CIDR ranges in command
                    if "/24" in command:
                        host_count = 254
                    elif "/16" in command:
                        host_count = min(1000, 65534)  # Cap for timeout calc
                    elif "/8" in command:
                        host_count = min(1000, 16777214)  # Cap for timeout calc

        except Exception as e:
            watchdog_logger.debug(f"[scan-monitor] Error extracting host count from job: {e}")
            host_count = 1

    # Scale timeout based on host count with diminishing returns
    if host_count <= 1:
        scale_factor = 1.0
    elif host_count <= 5:
        scale_factor = host_count * 0.8  # 80% per host for small scopes
    elif host_count <= 50:
        scale_factor = 4 + (host_count - 5) * 0.5  # 50% per additional host
    else:
        scale_factor = 26.5 + (host_count - 50) * 0.2  # 20% per additional host for large scopes

    calculated_timeout = int(base_timeout * scale_factor)

    # Apply reasonable limits
    max_timeout = 21600  # 6 hours max
    final_timeout = min(calculated_timeout, max_timeout)

    if host_count > 1:
        watchdog_logger.debug(
            f"[scan-monitor] Stage timeout for {stage}: {final_timeout}s "
            f"(base: {base_timeout}s, hosts: {host_count}, scale: {scale_factor:.1f}x)"
        )

    return final_timeout


def get_job_total_timeout(service_name: str, job_detail: dict = None) -> int:
    """Get total timeout for a job type - scales dynamically based on scan scope."""
    # Base total timeouts (for single host)
    base_timeouts = {
        "nmap": 3600,      # 1 hour base for nmap jobs
        "web": 2400,       # 40 minutes base for web scans
        "nuclei": 1800,    # 30 minutes base for nuclei
        "pd": 1200,        # 20 minutes base for port discovery
        "osint": 1800,     # 30 minutes base for OSINT
        "brutus": 3600,    # 1 hour base for brute force
        "playwright": 2400, # 40 minutes base for browser scans
    }

    base_timeout = base_timeouts.get(service_name, 3600)  # Default 1 hour base

    # Extract host count from job details (same logic as stage timeout)
    host_count = 1  # Default single host
    if job_detail:
        try:
            # Try various ways to extract host count
            targets = job_detail.get("targets", [])
            command = job_detail.get("command", "")

            if isinstance(targets, list):
                host_count = len(targets)
            elif isinstance(targets, str):
                host_count = len([t.strip() for t in targets.replace(" ", ",").split(",") if t.strip()])
            elif "target" in job_detail:
                target = job_detail["target"]
                if isinstance(target, str):
                    if "/" in target:
                        try:
                            import ipaddress
                            network = ipaddress.IPv4Network(target, strict=False)
                            host_count = min(network.num_addresses, 2000)  # Higher cap for total timeout
                        except:
                            host_count = 1
                    else:
                        host_count = len([t.strip() for t in target.replace(" ", ",").split(",") if t.strip()])

            # Parse command line for host indicators
            if host_count == 1 and command:
                if " -iL " in command or " --hostfile " in command:
                    host_count = 50
                elif any(cidr in command for cidr in ["/24", "/16", "/8"]):
                    if "/24" in command:
                        host_count = 254
                    elif "/16" in command:
                        host_count = min(2000, 65534)
                    elif "/8" in command:
                        host_count = min(2000, 16777214)

        except Exception as e:
            watchdog_logger.debug(f"[scan-monitor] Error extracting host count for total timeout: {e}")
            host_count = 1

    # Scale total timeout with more aggressive scaling than stage timeout
    if host_count <= 1:
        scale_factor = 1.0
    elif host_count <= 10:
        scale_factor = host_count * 0.9  # 90% per host for small scopes
    elif host_count <= 100:
        scale_factor = 9 + (host_count - 10) * 0.6  # 60% per additional host
    else:
        scale_factor = 63 + (host_count - 100) * 0.3  # 30% per additional host for very large scopes

    calculated_timeout = int(base_timeout * scale_factor)

    # Apply reasonable limits
    max_total_timeout = 28800  # 8 hours max total
    final_timeout = min(calculated_timeout, max_total_timeout)

    if host_count > 1:
        watchdog_logger.debug(
            f"[scan-monitor] Total timeout for {service_name}: {final_timeout}s "
            f"(base: {base_timeout}s, hosts: {host_count}, scale: {scale_factor:.1f}x)"
        )

    return final_timeout


async def recover_stuck_scan_job(service_url: str, service_name: str, job_id: str, headers: dict) -> bool:
    """Attempt to recover a stuck scan job."""
    try:
        import httpx

        # Try to restart or reset the job
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # First try to get job status to see if we can restart it
            response = await client.post(f"{service_url}/jobs/{job_id}/restart", headers=headers)

            if response.status_code == 200:
                return True

            # If restart endpoint doesn't exist, try to cancel and mark as failed
            cancel_response = await client.delete(f"{service_url}/jobs/{job_id}", headers=headers)
            return cancel_response.status_code in [200, 204]

    except Exception as e:
        watchdog_logger.error(f"[scan-monitor] Error recovering {service_name} job {job_id[:8]}: {e}")
        return False


async def mark_scan_job_failed(service_url: str, service_name: str, job_id: str, reason: str, headers: dict):
    """Force mark a scan job as failed."""
    try:
        import httpx

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # Try to update job status to failed
            update_data = {"status": "failed", "details": f"Marked as failed by AI watchdog: {reason}"}

            response = await client.patch(f"{service_url}/jobs/{job_id}",
                                        json=update_data, headers=headers)

            if response.status_code in [200, 204]:
                watchdog_logger.info(f"[scan-monitor] Marked {service_name} job {job_id[:8]} as failed")

                # Also update the scan record in the main database
                await update_scan_record_status(job_id, "failed", reason)
            else:
                watchdog_logger.warning(f"[scan-monitor] Failed to update {service_name} job {job_id[:8]} status: {response.status_code}")

    except Exception as e:
        watchdog_logger.error(f"[scan-monitor] Error marking {service_name} job {job_id[:8]} as failed: {e}")


async def update_scan_record_status(job_id: str, status: str, reason: str):
    """Update scan record status in the main database."""
    try:
        import httpx

        api_key = os.environ.get("API_KEY", "changeme")
        rag_api_url = os.environ.get("RAG_API_URL", "https://rag-api:8000")

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            update_data = {
                "job_id": job_id,
                "status": status,
                "details": reason
            }

            response = await client.post(f"{rag_api_url}/scans/update-status",
                                       json=update_data,
                                       headers={"x-api-key": api_key})

            if response.status_code == 200:
                watchdog_logger.info(f"[scan-monitor] Updated scan record {job_id[:8]} status to {status}")

    except Exception as e:
        watchdog_logger.error(f"[scan-monitor] Error updating scan record {job_id[:8]}: {e}")


async def cleanup_completed_job_tracking():
    """Clean up tracking for jobs that are no longer active."""
    try:
        # Remove tracking for jobs older than 24 hours (they're definitely done)
        cutoff_time = datetime.utcnow() - timedelta(hours=24)

        stale_jobs = [
            job_id for job_id, info in scan_job_tracking.items()
            if info.get("start_time", datetime.utcnow()) < cutoff_time
        ]

        for job_id in stale_jobs:
            if job_id in scan_job_tracking:
                del scan_job_tracking[job_id]
            if job_id in scan_job_recovery_attempts:
                del scan_job_recovery_attempts[job_id]

        if stale_jobs:
            watchdog_logger.debug(f"[scan-monitor] Cleaned up tracking for {len(stale_jobs)} old jobs")

    except Exception as e:
        watchdog_logger.error(f"[scan-monitor] Error cleaning up job tracking: {e}")


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize database schema, log capture, and session watchdog on startup"""
    import sys
    import asyncio

    # Ensure all required tables exist (idempotent)
    try:
        ensure_schema()
        print("✓ Database schema verified", file=sys.stderr)
    except Exception as e:
        print(f"⚠ Database schema check failed: {e}", file=sys.stderr)

    setup_log_capture()
    print("✓ Log capture web interface enabled at /logs/ui", file=sys.stderr)

    # Start session watchdog if enabled
    if SESSION_WATCHDOG_ENABLED:
        asyncio.create_task(session_watchdog())
        recovery_status = f"auto-recovery={'ON' if SESSION_AUTO_RECOVERY_ENABLED else 'OFF'}"
        print(f"✓ Session watchdog enabled (timeout={SESSION_STALL_TIMEOUT}s, {recovery_status})", file=sys.stderr)
    else:
        print("⚠ Session watchdog disabled", file=sys.stderr)

    # Start exploit watcher if enabled
    if EXPLOIT_WATCHER_ENABLED:
        asyncio.create_task(start_exploit_watcher())
        print("✓ Exploit watcher enabled - will auto-search for exploits on high-severity vulns", file=sys.stderr)
    else:
        print("⚠ Exploit watcher disabled", file=sys.stderr)

    # Register webhook with rag-api for scan completion events
    try:
        rag_api_url = os.environ.get("RAG_API_URL", "https://rag-api:8000")
        webhook_name = "autogen-scan-events"
        callback_url = "https://autogen-agents:8015/webhooks/scan-events"
        event_types = ["scan_completed", "scan_failed"]

        api_key = os.environ.get("API_KEY", "changeme")
        headers = {"x-api-key": api_key}

        async with httpx.AsyncClient(timeout=10, verify=False, headers=headers) as client:
            # Check if webhook already exists
            existing = await client.get(f"{rag_api_url}/webhooks")
            webhook_id = None
            if existing.status_code == 200:
                data = existing.json()
                webhook_list = data.get("webhooks", data) if isinstance(data, dict) else data
                for wh in webhook_list:
                    if wh.get("name") == webhook_name:
                        webhook_id = wh.get("id")
                        break

            payload = {
                "name": webhook_name,
                "url": callback_url,
                "event_types": event_types,
                "sources": None,
                "enabled": True,
            }

            if webhook_id:
                resp = await client.put(f"{rag_api_url}/webhooks/{webhook_id}", json=payload)
            else:
                resp = await client.post(f"{rag_api_url}/webhooks", json=payload)

            if resp.status_code in (200, 201):
                print(f"✓ Registered webhook '{webhook_name}' for scan events", file=sys.stderr)
            else:
                print(f"⚠ Webhook registration returned {resp.status_code}: {resp.text}", file=sys.stderr)
    except Exception as e:
        print(f"⚠ Could not register scan-events webhook (rag-api may be unavailable): {e}", file=sys.stderr)


@app.post("/webhooks/scan-events")
async def receive_scan_event(payload: dict):
    """
    Receive scan completion/failure webhooks from rag-api dispatcher.
    Wakes up any agent thread waiting on the corresponding job_id.
    """
    event_type = payload.get("event_type", "")
    data = payload.get("data", {})
    job_id = data.get("job_id", "")

    if not job_id:
        webhook_logger.warning(f"Webhook received without job_id: {event_type}")
        return {"ok": True, "matched": False}

    webhook_logger.info(f"Job completion webhook received: event={event_type} job_id={job_id[:8]}...")

    with _job_events_lock:
        entry = _job_events.get(job_id)
        if entry:
            entry["result"] = payload
            entry["event"].set()
            webhook_logger.info(f"Woke up waiter for job {job_id[:8]}")
            return {"ok": True, "matched": True}

    # No waiter — the usual case for a job that outlived its session. This is
    # exactly the scan whose results the teardown snapshot missed, so refresh the
    # summary now that it has landed. Runs in a thread: this handler is async and
    # the refresh does blocking DB work.
    #
    # Only for sessions that have ENDED. A live session still owns its in-memory
    # registry and will build a complete summary at its own teardown; refreshing
    # underneath it would race that.
    refreshed = False
    try:
        # Function-local, matching this module's convention — asyncio is not
        # imported at module scope here.
        import asyncio
        sess_id, sess_status = _session_id_for_job(job_id)
        if sess_id and sess_status not in ("active", "running", None):
            await asyncio.to_thread(_refresh_flow_summary, sess_id)
            refreshed = True
    except Exception as e:
        webhook_logger.warning(f"Post-session summary refresh failed for {job_id[:8]}: {e}")

    webhook_logger.debug(f"No waiter registered for job {job_id[:8]} (may have already completed)")
    return {"ok": True, "matched": False, "summary_refreshed": refreshed}



def _emit_flow_summary(session_id) -> dict:
    """End-of-session summary of what each SCAN TYPE actually did.

    Runs BEFORE cleanup_session(), which discards the in-memory scan registry this
    is built from. Every step is individually guarded: a reporting failure must
    never take down the session teardown around it — a missing summary is a
    nuisance, a crashed teardown leaks the session.
    """
    import json as _json
    try:
        summary = scan_tracker.build_flow_summary(str(session_id))
    except Exception as e:
        session_logger.warning("[%s] flow summary build failed: %s", session_id, e)
        return {}

    # Record which types were STILL RUNNING when this snapshot was taken.
    #
    # Teardown regularly happens while scans are in flight — on a real session,
    # udp and credential_check were both still running, and credential_check is
    # the one that finds valid credentials. Their results are simply absent from
    # this snapshot, which otherwise reads as a complete and final account.
    #
    # _refresh_flow_summary() fills them in once the scan-completed webhooks
    # arrive; until then this field is what tells a reader the numbers are
    # provisional rather than a scan that genuinely found nothing.
    try:
        in_flight = sorted({
            t.get("scan_type") for t in (summary.get("by_scan_type") or [])
            if (t.get("running") or 0) > 0
        } - {None})
        summary["in_flight_at_teardown"] = in_flight
        if in_flight:
            session_logger.info(
                "[%s] flow summary taken with %d type(s) still running: %s "
                "— will refresh on scan completion",
                session_id, len(in_flight), ", ".join(in_flight),
            )
    except Exception:
        summary["in_flight_at_teardown"] = []

    # Persist onto the session row so it outlives the process.
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE agent_sessions "
                    "SET metadata = COALESCE(metadata, '{}'::jsonb) || %s::jsonb "
                    "WHERE id = %s::uuid",
                    (_json.dumps({"scan_flow_summary": summary}), str(session_id)),
                )
            conn.commit()
    except Exception as e:
        session_logger.warning("[%s] flow summary persist failed: %s", session_id, e)

    # Webhook, per project convention: features that perform actions emit one so
    # Slack/n8n subscribers can react without polling.
    try:
        api_base = os.environ.get("API_BASE", "https://rag-api:8000")
        with httpx.Client(verify=False, timeout=10) as c:
            c.post(
                f"{api_base}/webhooks/emit",
                headers={"x-api-key": os.environ.get("API_KEY", "changeme")},
                json={
                    "event_type": "agent_session_flow_summary",
                    "source": "autogen-agents",
                    "data": {
                        "session_id": str(session_id),
                        "scan_types_run": summary.get("scan_types_run"),
                        "total_scans": summary.get("total_scans"),
                        "flow_order": summary.get("flow_order"),
                        "types_that_produced_nothing": summary.get("types_that_produced_nothing"),
                        "types_with_failures": summary.get("types_with_failures"),
                    },
                },
            )
    except Exception as e:
        session_logger.warning("[%s] flow summary webhook failed: %s", session_id, e)

    # Human-readable trace into the session log, which is what an operator reads.
    session_logger.info(
        "[%s] ===== SCAN FLOW SUMMARY: %s scan type(s), %s scan(s) =====",
        session_id, summary.get("scan_types_run"), summary.get("total_scans"),
    )
    session_logger.info(
        "[%s] flow: %s", session_id,
        " -> ".join(summary.get("flow_order") or []) or "(no scans ran)",
    )
    for t in (summary.get("by_scan_type") or []):
        produced = ", ".join(f"{k}={v}" for k, v in (t.get("results") or {}).items()) or "nothing"
        session_logger.info(
            "[%s]   %-22s runs=%s completed=%s failed=%s  %ss  produced: %s",
            session_id, t.get("scan_type"), t.get("runs"), t.get("completed"),
            t.get("failed"), t.get("total_duration_seconds"), produced,
        )
        for f in (t.get("failures") or []):
            session_logger.info("[%s]     FAILED %s: %s", session_id,
                                f.get("job_id"), f.get("error"))
    kb = summary.get("kb_coverage") or {}
    if kb.get("available") and kb.get("recommendations"):
        session_logger.info(
            "[%s]   KB coverage: acted on %s/%s recommendation(s) (%s%%), sources: %s",
            session_id, kb.get("acted_on"), kb.get("recommendations"),
            kb.get("coverage_pct"), kb.get("by_source"),
        )
        for r in (kb.get("recommended_but_never_run") or [])[:8]:
            session_logger.warning(
                "[%s]     RECOMMENDED BUT NEVER RUN: %s (x%s, priority %s)",
                session_id, r.get("scanner"), r.get("recommended"), r.get("top_priority"),
            )
    elif kb.get("available"):
        session_logger.info("[%s]   KB coverage: no recommendations for these targets", session_id)

    if summary.get("types_that_produced_nothing"):
        session_logger.warning(
            "[%s]   completed but produced NOTHING: %s "
            "— these read as success in every other view",
            session_id, ", ".join(summary["types_that_produced_nothing"]),
        )
    return summary




def _enable_recon_agent_if_requested(engagement_id, enabled, interval_sec) -> None:
    """Turn on the continuous recon agent for this engagement at session launch.

    recon_agent_state was EMPTY for every engagement, so Phase 4 — the loop that
    drains the KB recommendation queue — had never executed once. Enabling it was
    a manual step nothing prompted you to take, which is why 166 recommendations
    accumulated unread.

    Off unless asked for: the recon agent dispatches scans on a timer, so it is an
    explicit choice per session, with an ENABLE_RECON_AGENT_ON_LAUNCH env default.
    Scope enforcement still applies at the scanner.
    """
    if enabled is None:
        enabled = os.environ.get("ENABLE_RECON_AGENT_ON_LAUNCH", "false").strip().lower() in (
            "1", "true", "yes", "on")
    if not enabled:
        return
    if not engagement_id:
        session_logger.warning(
            "enable_recon_agent requested but no X-Engagement-Id was supplied — "
            "the recon agent is scoped per engagement, so there is nothing to enable")
        return
    try:
        bff = os.environ.get("BFF_URL", "https://pentest-dashboard")
        with httpx.Client(verify=False, timeout=30) as c:
            r = c.post(
                f"{bff}/api/recon-agent/{engagement_id}/enable",
                json={"interval_sec": int(interval_sec or 300),
                      "config": {"kb_driven_recon": True}},
                headers={"x-api-key": os.environ.get("API_KEY", "changeme")},
            )
        session_logger.info(
            "recon agent enable for engagement %s -> HTTP %s", engagement_id, r.status_code)
    except Exception as e:
        session_logger.warning("recon agent enable failed for %s: %s", engagement_id, e)



def _validate_agent_output(session_id, summary) -> dict:
    """Check what the agents CLAIMED against what the scans actually recorded.

    scan-recommender has had /kb/agent-output/verify since the claim-validation
    work — regex + SQL, deterministic, catching fabricated ports/CVEs/hosts. But
    nothing ever called it: it only ran if a human POSTed to it by hand, so in
    practice no session's output was ever validated. Running it here, at the same
    teardown point as the flow summary, is what makes it actually happen.

    Deliberately NOT the LLM path (use_llm stays false): the regex+SQL pass is
    deterministic, and asking a second model to judge the first adds another thing
    that can hallucinate. Ports, CVEs, services and hosts all have exact database
    answers.

    Caveat worth carrying into the log: broken ingestion makes every claim look
    unsupported, so this is read alongside the flow summary's produced/failed
    counts, not on its own.
    """
    import json as _json
    try:
        msgs = get_agent_messages(session_id, limit=400) or []
    except Exception as e:
        session_logger.warning("[%s] claim validation: could not read messages: %s",
                               session_id, e)
        return {}
    text = "\n".join(
        str(m.get("content") or "") for m in msgs
        if (m.get("role") or "").lower() in ("assistant", "agent", "")
    ).strip()
    if not text:
        return {}

    # Validate against the host the session actually scanned.
    targets = []
    for t in (summary or {}).get("by_scan_type", []) or []:
        targets.extend(t.get("targets") or [])
    ip = None
    for t in targets:
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", str(t))
        if m:
            ip = m.group(1)
            break

    try:
        rec_url = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
        with httpx.Client(verify=False, timeout=60) as c:
            r = c.post(f"{rec_url}/kb/agent-output/verify",
                       json={"session_id": str(session_id), "text": text[:60000],
                             "ip": ip, "use_llm": False},
                       headers={"x-api-key": os.environ.get("API_KEY", "changeme")})
        if r.status_code >= 400:
            session_logger.warning("[%s] claim validation HTTP %s: %s",
                                   session_id, r.status_code, r.text[:160])
            return {}
        v = r.json()
    except Exception as e:
        session_logger.warning("[%s] claim validation failed: %s", session_id, e)
        return {}

    session_logger.info(
        "[%s] CLAIM VALIDATION — %s claim(s) checked, %s unsupported%s",
        session_id, v.get("claims_checked"), v.get("unsupported_count"),
        " (POSSIBLE RUN FAILURE)" if v.get("probable_run_failure") else "",
    )
    for u in (v.get("unsupported") or [])[:10]:
        session_logger.warning("[%s]   UNSUPPORTED %s: %s", session_id,
                               u.get("kind"), str(u.get("value"))[:80])
    if v.get("probable_run_failure"):
        session_logger.warning(
            "[%s]   run-failure hint: %s — unsupported claims can also mean "
            "INGESTION broke, not that the agent invented them; check the flow "
            "summary's produced counts before treating these as fabrication",
            session_id, v.get("run_failure_hint"))

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE agent_sessions "
                    "SET metadata = COALESCE(metadata, '{}'::jsonb) || %s::jsonb "
                    "WHERE id = %s::uuid",
                    (_json.dumps({"claim_validation": v}), str(session_id)),
                )
            conn.commit()
    except Exception as e:
        session_logger.warning("[%s] claim validation persist failed: %s", session_id, e)

    try:
        api_base = os.environ.get("API_BASE", "https://rag-api:8000")
        with httpx.Client(verify=False, timeout=10) as c:
            c.post(f"{api_base}/webhooks/emit",
                   headers={"x-api-key": os.environ.get("API_KEY", "changeme")},
                   json={"event_type": "agent_output_validated",
                         "source": "autogen-agents",
                         "data": {"session_id": str(session_id),
                                  "claims_checked": v.get("claims_checked"),
                                  "unsupported_count": v.get("unsupported_count"),
                                  "probable_run_failure": v.get("probable_run_failure")}})
    except Exception as e:
        session_logger.warning("[%s] claim validation webhook failed: %s", session_id, e)
    return v


def _drain_recommendations_if_enabled(session_id, summary, enabled) -> None:
    """Dispatch the KB recommendations this run generated but never acted on.

    The post-ingest recommender writes scan_recommendations per discovered
    (ip, service). Nothing consumed them: a real engagement finished with 166 rows
    at status='pending', including 41 metasploit and 5 hydra recommendations, and
    no view surfaced that. This closes the loop at the point where the session's
    own coverage is already known.

    Off unless asked for. Draining the queue dispatches real scans at real hosts,
    so it is opt-in per session (auto_run_recommendations) with an
    AUTO_RUN_RECOMMENDATIONS env default. Scope enforcement still applies at the
    scanner — this cannot reach a host the engagement is not authorized for.
    """
    if enabled is None:
        enabled = os.environ.get("AUTO_RUN_RECOMMENDATIONS", "false").strip().lower() in (
            "1", "true", "yes", "on")
    if not enabled:
        return

    kb = (summary or {}).get("kb_coverage") or {}
    if not kb.get("available"):
        session_logger.info(
            "[%s] auto-run recommendations: skipped, KB coverage unavailable (%s)",
            session_id, kb.get("reason", "unknown"))
        return
    if not kb.get("ignored"):
        session_logger.info(
            "[%s] auto-run recommendations: nothing pending to run", session_id)
        return

    try:
        bff = os.environ.get("BFF_URL", "https://pentest-dashboard")
        hdr = {"x-api-key": os.environ.get("API_KEY", "changeme")}
        with httpx.Client(verify=False, timeout=60) as c:
            # Ask the recommender for the pending set rather than reconstructing
            # it here — that endpoint already owns status writeback and dedupe
            # against in-flight jobs.
            r = c.get(f"{bff}/api/scan-recommendations",
                      params={"status": "pending", "limit": 200}, headers=hdr)
            recs = (r.json().get("recommendations") or []) if r.status_code == 200 else []
            ids = [x.get("id") for x in recs if x.get("id")]
            if not ids:
                session_logger.info(
                    "[%s] auto-run recommendations: queue empty at dispatch time",
                    session_id)
                return
            run = c.post(f"{bff}/api/scan-recommendations/run",
                         json={"ids": ids}, headers=hdr)
            session_logger.info(
                "[%s] auto-run recommendations: dispatched %s rec(s) -> HTTP %s",
                session_id, len(ids), run.status_code)
    except Exception as e:
        # Never let this take down the teardown around it.
        session_logger.warning(
            "[%s] auto-run recommendations failed: %s", session_id, e)


def _session_id_for_job(job_id: str):
    """Which session owns this scan job, and had it already ended?

    session_scan_metrics is the link. It is only reliable now that persist_to_db
    upserts on (session_id, job_id) — before that it re-inserted on every call,
    so a job could match several rows carrying different statuses.
    """
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT m.session_id::text, s.status "
                    "  FROM session_scan_metrics m "
                    "  LEFT JOIN agent_sessions s ON s.id = m.session_id "
                    " WHERE m.job_id = %s "
                    " ORDER BY m.created_at DESC LIMIT 1",
                    (str(job_id),),
                )
                row = cur.fetchone()
                if not row:
                    return None, None
                return row[0], row[1]
    except Exception as e:
        webhook_logger.debug("job->session lookup failed for %s: %s", job_id, e)
        return None, None


def _refresh_flow_summary(session_id) -> None:
    """Re-build the flow summary for an ENDED session from persisted scan rows.

    The teardown snapshot is taken while scans are often still running, so it
    under-reports. This runs when a scan-completed webhook arrives for a session
    that has already finished, and replaces the snapshot with one that includes
    the late results.

    It must read from session_scan_metrics rather than the in-memory registry:
    cleanup_session() has already discarded that, and build_flow_summary() would
    otherwise cheerfully report a session with zero scans and overwrite a good
    summary with an empty one.

    Claim validation is re-run afterwards for the same reason it exists: with
    ingestion now complete, claims that looked "unsupported" purely because their
    scan had not finished get a fair second evaluation.
    """
    import json as _json
    sid = str(session_id)
    try:
        scans = scan_tracker.load_scans_from_db(sid)
        if not scans:
            return
        summary = scan_tracker.build_flow_summary(sid, scans=scans)
        if not summary.get("total_scans"):
            return
        summary["refreshed_at"] = datetime.utcnow().isoformat() + "Z"
        summary["in_flight_at_teardown"] = sorted({
            t.get("scan_type") for t in (summary.get("by_scan_type") or [])
            if (t.get("running") or 0) > 0
        } - {None})

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE agent_sessions "
                    "SET metadata = COALESCE(metadata, '{}'::jsonb) || %s::jsonb "
                    "WHERE id = %s::uuid",
                    (_json.dumps({"scan_flow_summary": summary}), sid),
                )
            conn.commit()
        webhook_logger.info(
            "[%s] flow summary refreshed: %d scans, %d types, still running: %s",
            sid[:8], summary.get("total_scans"), summary.get("scan_types_run"),
            summary.get("in_flight_at_teardown") or "none",
        )

        try:
            _validate_agent_output(session_id, summary)
        except Exception as e:
            webhook_logger.warning("[%s] revalidation failed: %s", sid[:8], e)
    except Exception as e:
        webhook_logger.warning("[%s] flow summary refresh failed: %s", sid[:8], e)


def _finalize_session(session_id, auto_run_recommendations) -> None:
    """Everything that must happen when a session ends, however it ended.

    This used to be inline at the bottom of the happy path, which meant the three
    most valuable steps — the flow summary, claim validation and the KB drain —
    ran ONLY when a session completed cleanly. Both `except` handlers persisted
    scan rows and cleaned up, but produced no summary and validated nothing.

    The `stalled` session in agent_sessions is what that looks like from the
    outside: no scan_flow_summary, no claim_validation, no termination metadata.
    A failed run is exactly when an operator most needs to know what each scan
    type produced and whether the agents' claims held up, so the reporting now
    runs from a `finally`.

    ORDER IS LOAD-BEARING. build_flow_summary() reads the in-memory scan registry
    that cleanup_session() discards, so every reporting step has to complete
    before cleanup. That is also why the except handlers no longer clean up
    themselves — doing so would wipe the registry before this function ran.

    Every step is individually guarded: reporting is a nicety, releasing the
    session is not, and a failure in the former must never strand the latter.
    """
    sid = str(session_id)
    summary = {}

    try:
        summary = _emit_flow_summary(session_id) or {}
    except Exception as e:
        session_logger.warning("[%s] flow summary failed: %s", sid, e)

    try:
        _validate_agent_output(session_id, summary)
    except Exception as e:
        session_logger.warning("[%s] claim validation failed: %s", sid, e)

    try:
        _drain_recommendations_if_enabled(session_id, summary, auto_run_recommendations)
    except Exception as e:
        session_logger.warning("[%s] recommendation drain failed: %s", sid, e)

    try:
        scan_tracker.persist_to_db(sid)
    except Exception as e:
        session_logger.warning("[%s] scan persist failed: %s", sid, e)

    try:
        LLMMetricsContext.flush_buffer()
        LLMMetricsContext.clear_session()
    except Exception as e:
        session_logger.warning("[%s] LLM metrics flush failed: %s", sid, e)

    # Release last — after this the registry is gone.
    try:
        scan_tracker.clear_session()
        scan_tracker.cleanup_session(sid)
    except Exception as e:
        session_logger.warning("[%s] scan tracker cleanup failed: %s", sid, e)

    active_sessions.pop(sid, None)


# Phase 4 flipped the default engine to LangGraph; Phase 5 RETIRED AutoGen
# (Docs/LANGGRAPH_MIGRATION_PLAN.md). `pyautogen` is gone from requirements and
# nothing imports `autogen`, so "langgraph" is the only engine there is.
#
# The `engine` request field and AGENT_ENGINE env var are KEPT rather than
# deleted, for two reasons: existing callers, saved launch presets and scripts
# still send them, and an operator who sets AGENT_ENGINE=autogen deserves a
# warning in the log rather than a 500 or — worse — silence.
DEFAULT_AGENT_ENGINE = "langgraph"
VALID_AGENT_ENGINES = ("langgraph",)
# Accepted at the API and answered with a warning, not an error.
RETIRED_AGENT_ENGINES = ("autogen",)


def resolve_agent_engine(requested: Optional[str] = None) -> str:
    """Which engine runs a session. Always "langgraph" now.

    A retired or unknown value is logged and overridden rather than honoured:
    running a different engine than the caller asked for while saying nothing is
    how an A/B comparison becomes a lie, and failing the request outright would
    break launch presets saved before the retirement.
    """
    for source, value in (("request", requested),
                          ("AGENT_ENGINE", os.environ.get("AGENT_ENGINE"))):
        v = (value or "").strip().lower()
        if not v:
            continue
        if v in VALID_AGENT_ENGINES:
            return v
        if v in RETIRED_AGENT_ENGINES:
            session_logger.warning(
                "Agent engine %r (from %s) was RETIRED in migration Phase 5 — "
                "pyautogen is no longer installed. Running %r instead.",
                v, source, DEFAULT_AGENT_ENGINE)
        else:
            session_logger.warning(
                "Ignoring unknown agent engine %r from %s; using %r (valid: %s)",
                v, source, DEFAULT_AGENT_ENGINE, ", ".join(VALID_AGENT_ENGINES))
        return DEFAULT_AGENT_ENGINE
    return DEFAULT_AGENT_ENGINE


def run_pentest_session_sync(
    session_id: uuid.UUID,
    target_description: str,
    initial_task: str,
    max_rounds: int = 200,
    resume_context: Optional[str] = None,
    session_name: str = "unnamed",
    auto_execute_scans: bool = True,
    proxy: Optional[str] = None,
    port_profile: Optional[str] = None,
    web_profile: Optional[str] = None,
    auto_run_recommendations: Optional[bool] = None,
    engine: Optional[str] = None,
    exploit_phase: Optional[bool] = None,
    surface_test_phase: Optional[bool] = None,
    surface_target: Optional[str] = None,
    synthesize_tests: Optional[bool] = None,
):
    """Run a pentest session. Delegates to the LangGraph engine.

    This used to be ~570 lines of AutoGen GroupChat orchestration: build a
    PentestTeam, wire a GroupChat + GroupChatManager, poll `groupchat.messages`
    on a flusher thread, and interpret `_termination_reason` afterwards. All of
    it was retired with AutoGen (Docs/LANGGRAPH_MIGRATION_PLAN.md, Phase 5); the
    LangGraph engine carries the whole lifecycle, including the parts that used
    to live only here (session output collection, scan metadata, and
    `_finalize_session`).

    `engine` is kept in the signature so callers that pass it still work; the
    only accepted value is now "langgraph" (see resolve_agent_engine).

    Args:
        session_id: Session UUID
        target_description: Description of target
        initial_task: Initial task for the agents
        max_rounds: Retained for API compatibility; the graph's phases are
            deterministic, so it bounds nothing. Reported unchanged in the
            session configuration.
        resume_context: Optional context from a parent session being resumed
        auto_execute_scans: Whether the scan phase may dispatch, or only plan.
            Enforced by the phase's TOOLSET, not by a prompt.
        proxy: SOCKS proxy URL for routing scans through a remote node
        port_profile: Named port scope applied to every discovery scan this
            session runs (see knowledge/port_profiles.yaml).
        web_profile: Named web scan depth for this session's web tools.
        auto_run_recommendations: Dispatch KB recommendations the session
            generated but never acted on, when it ends.
        exploit_phase: Add the human-approved exploit phase. The session PAUSES
            on a durable interrupt until an operator answers /approve.
    """
    resolve_agent_engine(engine)  # validates + warns on an unknown value
    from langgraph_engine import run_langgraph_session_sync
    return run_langgraph_session_sync(
        session_id, target_description, initial_task, max_rounds,
        resume_context, session_name, auto_execute_scans, proxy,
        port_profile, web_profile, auto_run_recommendations,
        exploit_phase=exploit_phase,
        surface_test_phase=surface_test_phase,
        surface_target=surface_target,
        synthesize_tests=synthesize_tests)


@app.get("/health")
async def health():
    """
    Health check endpoint with dependency verification

    Returns service health status including:
    - Ollama LLM service availability
    - Active session count
    - Service URLs
    """
    from agent_config import get_llm_backend
    backend = get_llm_backend()

    llm_healthy, llm_msg = await check_llm_health(timeout=3)

    # Report the endpoint/model that were actually PROBED. Reading them from env
    # here contradicted the verdict beside them: the check resolves the dashboard
    # DB config, so /health showed `endpoint: ""` and `model: "gpt-4o"` next to
    # "DeepSeek-V4-Flash healthy" — two different backends in one object.
    try:
        from agent_config import get_llm_config
        _cfg = (get_llm_config() or [{}])[0]
    except Exception:
        _cfg = {}
    llm_dep_info = {
        "healthy": llm_healthy,
        "message": llm_msg,
        "endpoint": _cfg.get("base_url") or os.environ.get("AZURE_ENDPOINT", ""),
        "model": _cfg.get("model") or os.environ.get("AZURE_MODEL", ""),
        "api_type": _cfg.get("api_type"),
        "resolved_from": "dashboard-db" if _cfg.get("base_url") else "env",
    }
    if backend not in ("azure", "openai") and not _cfg.get("base_url"):
        llm_dep_info["url"] = os.environ.get("OLLAMA_URL", "http://ollama:11434")

    health_data = {
        "ok": llm_healthy,
        "service": "autogen-agents",
        "version": os.environ.get("BUILD_VERSION", "dev"),
        "llm_backend": backend,
        "active_sessions": len(active_sessions),
        "dependencies": {
            "llm": llm_dep_info,
        }
    }

    # Always a dict, always HTTP 200. Two deliberate decisions:
    #
    # 1. This used to `return (health_data, 503)` when a dependency was down.
    #    FastAPI does NOT read a returned tuple as (body, status) — it
    #    serialised it as a JSON ARRAY and still answered 200. So the intended
    #    503 never happened, and every consumer got `[{...}, 503]` instead of an
    #    object. That broke /api/diagnostics/session-bundle with
    #    `AttributeError: 'list' object has no attribute 'get'` on every call.
    # 2. Actually answering 503 would be worse than the bug: the Dockerfile
    #    HEALTHCHECK is `curl -f /health`, so an LLM outage would mark the
    #    CONTAINER unhealthy and block everything gated on it — while the
    #    service is still serving /sessions, /messages and /report perfectly
    #    well. Degradation belongs in the body, not in a status code that takes
    #    the container down.
    health_data["status"] = "healthy" if llm_healthy else "degraded"
    return health_data


@app.get("/health/system")
async def proxy_system_health():
    """
    Proxy endpoint to fetch comprehensive system health from rag-api.
    Used by the web log interface to display system status.
    """
    rag_api_url = os.environ.get("RAG_API_URL", "https://rag-api:8000")

    try:
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            response = await client.get(f"{rag_api_url}/health/")
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    "status": "error",
                    "message": f"Health check returned status {response.status_code}",
                    "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "health_percentage": 0},
                    "checks": [],
                    "ready_for_operations": False
                }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "message": "Health check request timed out",
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "health_percentage": 0},
            "checks": [],
            "ready_for_operations": False
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to fetch health status: {str(e)}",
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "health_percentage": 0},
            "checks": [],
            "ready_for_operations": False
        }


@app.post("/pentest", response_model=PentestResponse)
async def start_pentest(request: PentestRequest, http_request: Request = None):
    """
    Start a new multi-agent penetration testing session

    The agents will:
    1. Analyze the target description
    2. Plan reconnaissance strategy
    3. Execute scans using available tools
    4. Analyze findings
    5. Generate a comprehensive report
    """
    import asyncio

    try:
        # Create session in database
        # The resolved engine is persisted, not just the requested one: a
        # session that ran on autogen must still say so after AGENT_ENGINE is
        # flipped, or the A/B comparison the canary exists for is unreadable.
        engine = resolve_agent_engine(request.engine)
        session_id = create_agent_session(
            request.session_name,
            request.target_description,
            {
                "max_rounds": request.max_rounds,
                "auto_execute_scans": request.auto_execute_scans,
                "initial_task": request.initial_task,
                "proxy": request.proxy,
                "port_profile": request.port_profile,
                "web_profile": request.web_profile,
                "engine": engine,
                "enable_exploit_phase": bool(request.enable_exploit_phase),
                "enable_surface_test_phase": bool(request.enable_surface_test_phase),
                "surface_target_host": request.surface_target_host,
                "enable_test_synthesis": bool(request.enable_test_synthesis),
            }
        )

        # Log session creation
        session_logger.info(f"[{session_id}] New pentest session created: {request.session_name}")
        session_logger.info(f"[{session_id}] Target: {request.target_description[:100]}")
        session_logger.info(f"[{session_id}] Task: {request.initial_task[:100]}")

        # Start the pentest session in background using asyncio.to_thread
        # This runs the synchronous function in a thread pool to avoid blocking the event loop
        # Launch option: turn on the continuous recon agent for this engagement.
        _eid = None
        if http_request is not None:
            _eid = (http_request.headers.get("x-engagement-id")
                    or http_request.headers.get("X-Engagement-Id"))
        _enable_recon_agent_if_requested(
            _eid, request.enable_recon_agent, request.recon_agent_interval_sec)

        asyncio.create_task(
            asyncio.to_thread(
                run_pentest_session_sync,
                session_id,
                request.target_description,
                request.initial_task,
                request.max_rounds,
                None,  # resume_context
                request.session_name,
                request.auto_execute_scans,
                request.proxy,
                request.port_profile,
                request.web_profile,
                request.auto_run_recommendations,
                engine,
                request.enable_exploit_phase,
                request.enable_surface_test_phase,
                request.surface_target_host,
                request.enable_test_synthesis,
            )
        )

        return PentestResponse(
            session_id=str(session_id),
            status="running",
            message=f"Pentest session started successfully (engine={engine})"
        )

    except Exception as e:
        session_logger.error(f"Failed to start pentest: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start pentest: {str(e)}")


@app.post("/pentest/{session_id}/resume", response_model=PentestResponse)
async def resume_pentest(session_id: str, request: ResumeRequest):
    """
    Resume a failed/stalled/stopped pentest session.

    Creates a new session that inherits context from the parent session.
    Agents will see all previously discovered assets, ports, and findings
    (stored in global tables) and receive a summary of what was already done.
    """
    import asyncio
    from psycopg2.extras import Json

    try:
        parent_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    # Validate parent session exists
    parent = get_agent_session(parent_uuid)
    if not parent:
        raise HTTPException(status_code=404, detail="Session not found")

    # Only allow resuming non-active sessions
    resumable = {'failed', 'stalled', 'stopped', 'completed', 'rounds_exhausted', 'agent_failure'}
    if parent['status'] == 'awaiting_approval':
        # This session is not stuck — it is parked on a durable interrupt waiting
        # for a human decision. Resuming it as a NEW session would abandon the
        # checkpoint and re-run the phases already done, so name the right route.
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} is paused awaiting operator approval. "
                   f"Answer it with POST /pentest/{session_id}/approve "
                   '{"approved": true|false, "pending_exploit_id": "<uuid>"} — '
                   "that continues the SAME session from its Postgres checkpoint. "
                   f"See GET /pentest/{session_id}/pending-approval for what is pending."
        )
    if parent['status'] not in resumable:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot resume a session with status '{parent['status']}'. "
                   f"Only sessions with status {resumable} can be resumed."
        )

    # Check no active resume already running for this parent
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM agent_sessions
            WHERE parent_session_id = %s AND status = 'active'
            LIMIT 1
            """,
            (parent_uuid,)
        )
        if cur.fetchone():
            raise HTTPException(
                status_code=409,
                detail="An active resumed session already exists for this parent session"
            )

    # Build context from parent session
    resume_context = build_resume_context(parent_uuid)
    if not resume_context:
        raise HTTPException(status_code=500, detail="Failed to build resume context from parent session")

    # Retrieve the original task from configuration
    config = parent.get('configuration') or {}
    original_task = config.get('initial_task', 'Continue the penetration test')
    parent_name = parent['session_name']
    target_description = parent['target_description']

    # Create new session
    # Use new proxy if specified, otherwise inherit from parent
    proxy = request.proxy or config.get('proxy')
    new_session_id = create_agent_session(
        session_name=f"{parent_name}-resumed",
        target_description=target_description,
        configuration={
            "max_rounds": request.max_rounds,
            "auto_execute_scans": config.get('auto_execute_scans', True),
            "initial_task": original_task,
            "parent_session_id": str(parent_uuid),
            "proxy": proxy,
            # Inherit the parent's engine: a resume that silently switches
            # engines is not a resume of the same test.
            "engine": resolve_agent_engine(config.get('engine')),
            "enable_exploit_phase": bool(config.get('enable_exploit_phase')),
            "enable_surface_test_phase": bool(config.get('enable_surface_test_phase')),
            "surface_target_host": config.get('surface_target_host'),
            "enable_test_synthesis": bool(config.get('enable_test_synthesis')),
        }
    )

    # Set parent_session_id on the new session
    with get_db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE agent_sessions SET parent_session_id = %s, metadata = %s WHERE id = %s",
            (parent_uuid, Json({"parent_session_id": str(parent_uuid)}), new_session_id)
        )
        conn.commit()

    # Build the enriched initial task
    enriched_task = original_task
    if request.additional_instructions:
        enriched_task = f"{original_task}\n\nAdditional instructions: {request.additional_instructions}"

    session_logger.info(f"[{new_session_id}] Resuming session from parent {session_id}")
    session_logger.info(f"[{new_session_id}] Target: {target_description}")

    # Launch in background — use new proxy if specified, otherwise inherit from parent
    auto_execute = config.get('auto_execute_scans', True)
    proxy = request.proxy or config.get('proxy')
    asyncio.create_task(
        asyncio.to_thread(
            run_pentest_session_sync,
            new_session_id,
            target_description,
            enriched_task,
            request.max_rounds,
            resume_context,
            f"{parent_name}-resumed",
            auto_execute,
            proxy,
            config.get('port_profile'),
            config.get('web_profile'),
            None,  # auto_run_recommendations
            resolve_agent_engine(config.get('engine')),
            bool(config.get('enable_exploit_phase')),
            bool(config.get('enable_surface_test_phase')),
            config.get('surface_target_host'),
            bool(config.get('enable_test_synthesis')),
        )
    )

    return PentestResponse(
        session_id=str(new_session_id),
        status="running",
        message=f"Resumed session from parent {session_id}"
    )


@app.get("/pentest/mcp-tools")
async def list_mcp_tools_for_agents():
    """List MCP tools available to the autogen agents."""
    try:
        from mcp_tools_bridge import _discover_tools_sync, BUILTIN_MCP_SERVERS, _get_third_party_servers, NATIVE_TOOL_NAMES
        all_servers = list(BUILTIN_MCP_SERVERS) + _get_third_party_servers()
        all_tools = _discover_tools_sync(all_servers)
        new_tools = [t for t in all_tools if t.name not in NATIVE_TOOL_NAMES]
        return {
            "total_discovered": len(all_tools),
            "native_duplicates": len(all_tools) - len(new_tools),
            "registered_for_agents": len(new_tools),
            "servers": {s: sum(1 for t in new_tools if t.server_name == s)
                        for s in set(t.server_name for t in new_tools)},
            "tools": [
                {"name": t.name, "server": t.server_name, "description": t.description[:200]}
                for t in new_tools
            ],
        }
    except Exception as e:
        return {"error": str(e), "total_discovered": 0, "registered_for_agents": 0}


@app.get("/pentest/sessions")
async def list_pentest_sessions(
    status: Optional[str] = None,
    limit: int = 50
):
    """
    List all pentest sessions with optional filtering
    """
    sessions = list_agent_sessions(status=status, limit=limit)
    return {
        "sessions": [
            {
                "session_id": str(s['id']),
                "session_name": s['session_name'],
                "status": s['status'],
                "target_description": s['target_description'],
                "created_at": s['created_at'].isoformat() if s['created_at'] else None,
                "end_time": s['end_time'].isoformat() if s.get('end_time') else None,
                "error": s.get('summary') if s['status'] == 'failed' else None
            }
            for s in sessions
        ],
        "total": len(sessions)
    }


@app.get("/pentest/watchdog")
async def get_watchdog_status():
    """
    Get enhanced AI watchdog status - monitors both sessions and scan jobs.

    Returns information about:
    - Watchdog configuration (enabled, timeout, interval)
    - Auto-recovery configuration and status
    - Currently tracked AI sessions with their stall status
    - Currently tracked scan jobs with their progress status
    """
    now = datetime.utcnow()

    tracked_sessions = []
    for session_id_key, last_activity in session_last_activity.items():
        stall_time = (now - last_activity).total_seconds()
        message_count = session_last_message_count.get(session_id_key, 0)
        recovery_attempts = session_recovery_attempts.get(session_id_key, 0)

        # Get dynamic timeout for this session
        session_timeout = get_session_timeout(session_id_key)

        # Determine status based on stall time and recovery attempts
        if stall_time >= session_timeout:
            status = "stalled" if recovery_attempts >= SESSION_MAX_RECOVERY_ATTEMPTS else "recovering"
        elif stall_time >= session_timeout / 2:
            status = "stalling"
        else:
            status = "healthy"

        tracked_sessions.append({
            "session_id": session_id_key,
            "last_activity": last_activity.isoformat(),
            "stall_time_seconds": round(stall_time, 1),
            "message_count": message_count,
            "status": status,
            "will_stall_in": max(0, round(session_timeout - stall_time, 1)),
            "dynamic_timeout": session_timeout,
            "recovery_attempts": recovery_attempts,
            "max_recovery_attempts": SESSION_MAX_RECOVERY_ATTEMPTS,
            "in_memory": session_id_key in active_sessions
        })

    return {
        "watchdog_enabled": SESSION_WATCHDOG_ENABLED,
        "stall_timeout_seconds": SESSION_STALL_TIMEOUT,
        "check_interval_seconds": SESSION_WATCHDOG_INTERVAL,
        "auto_recovery": {
            "enabled": SESSION_AUTO_RECOVERY_ENABLED,
            "max_attempts": SESSION_MAX_RECOVERY_ATTEMPTS
        },
        "tracked_sessions": tracked_sessions,
        "active_sessions_in_memory": len(active_sessions),
        "scan_job_monitoring": {
            "enabled": True,
            "tracked_jobs": len(scan_job_tracking),
            "jobs_with_recovery_attempts": len(scan_job_recovery_attempts),
            "tracked_job_details": [
                {
                    "job_id": job_id[:8],
                    "service": info["service_name"],
                    "stage": info["last_stage"],
                    "running_time": round((now - info["start_time"]).total_seconds(), 1),
                    "stage_duration": round((now - info["stage_start_time"]).total_seconds(), 1),
                    "recovery_attempts": scan_job_recovery_attempts.get(job_id, 0)
                }
                for job_id, info in scan_job_tracking.items()
            ]
        }
    }


@app.get("/pentest/engine")
async def get_agent_engine():
    """Which orchestration engine new sessions use, and whether each is loadable.

    Declared BEFORE /pentest/{session_id} on purpose: FastAPI matches in
    declaration order, so after the parameterised route this path would be
    swallowed as a session id. tests/test_route_contracts.py enforces that.
    """
    resolved = resolve_agent_engine(None)
    availability = {}
    for name, module in (("langgraph", "langgraph_engine"),):
        try:
            __import__(module)
            availability[name] = {"available": True, "error": None}
        except Exception as e:  # noqa: BLE001
            availability[name] = {"available": False, "error": f"{type(e).__name__}: {e}"[:200]}
    return {
        "engine": resolved,
        "default": DEFAULT_AGENT_ENGINE,
        "env_AGENT_ENGINE": os.environ.get("AGENT_ENGINE") or None,
        "valid": list(VALID_AGENT_ENGINES),
        "retired": list(RETIRED_AGENT_ENGINES),
        "retired_note": ("AutoGen was retired in migration Phase 5; pyautogen is "
                         "not installed. Requests naming it are logged and run on "
                         "langgraph."),
        "exploit_phase_default": os.environ.get("LANGGRAPH_EXPLOIT_PHASE") or None,
        "surface_test_phase_default": os.environ.get("LANGGRAPH_SURFACE_TEST_PHASE") or None,
        "test_synthesis_default": os.environ.get("LANGGRAPH_SYNTH_TESTS") or None,
        "availability": availability,
    }


class SynthesizeTestRequest(BaseModel):
    issue_type: Optional[str] = None
    cwe: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None
    target: Optional[str] = None
    cve: Optional[str] = None          # pull an ExploitDB writeup as extra guidance
    edb_id: Optional[str] = None       # or a specific ExploitDB entry
    session_id: Optional[str] = None
    persist: bool = True


@app.post("/synthesize-test")
async def synthesize_test(req: SynthesizeTestRequest):
    """LLM-author a CUSTOM security test for one web finding (prototype of the
    'move past straight tools' direction).

    Matches the finding to its WSTG guidance, asks the RESOLVED LLM backend to
    write a concrete command + machine-checkable assertion, then FAIL-SAFE
    classifies the synthesized command (the model's own opinion cannot upgrade a
    test into the safe lane). A safe candidate is persisted (enabled) and re-runs
    through the scope-gated executor; an impactful candidate is returned for
    approval and NOT persisted (the security_tests lane check needs a
    pending_exploit_id). This never executes anything.
    """
    import json as _json
    import scan_tools
    import test_synth
    import db_utils as _db
    guidance, matched, edb_used = "", None, None
    try:
        g = _json.loads(scan_tools.get_wstg_guidance(
            issue_type=req.issue_type, cwe=req.cwe, name=req.name,
            target=req.target, url=req.url))
        guidance = g.get("guidance") or ""
        matched = (g.get("entry") or {}).get("wstg_id") if g.get("matched") else None
    except Exception:  # noqa: BLE001
        pass
    # ExploitDB writeup as additional guidance when a CVE/EDB id is supplied (or a
    # CVE was passed in `cwe`). Most ExploitDB-derived tests are real exploits, so
    # they will fail-safe classify impactful and stay approval-gated.
    if req.cve or req.edb_id or (req.cwe and req.cwe.upper().startswith("CVE-")):
        try:
            ed = _json.loads(scan_tools.get_exploitdb_guidance(
                cve=req.cve or (req.cwe if (req.cwe or "").upper().startswith("CVE-") else None),
                edb_id=req.edb_id))
            if ed.get("matched"):
                edb_used = (ed.get("top") or {}).get("edb_id")
                guidance = (guidance + "\n\n=== ExploitDB writeup ===\n"
                            + (ed.get("guidance") or ""))[:8000]
        except Exception:  # noqa: BLE001
            pass
    finding = {"issue_type": req.issue_type, "cwe": req.cve or req.cwe,
               "name": req.name, "url": req.url, "target": req.target}
    out = test_synth.synthesize(finding, guidance)
    if not out.get("ok"):
        raise HTTPException(502, out.get("error") or "synthesis failed")
    spec = out["spec"]
    persisted_id = None
    if req.persist and spec["tier"] == "safe":
        try:
            persisted_id = _db.create_security_test(
                name=spec["name"], tier="safe", category=spec["category"],
                target_ip=((req.target or "").split(":")[0] or None),
                command=spec["command"], tool=spec["tool"],
                assertion=spec["assertion"], created_by_session=req.session_id)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(500, f"persist failed: {e}")
    return {"ok": True, "spec": spec, "matched_wstg": matched,
            "matched_exploitdb": edb_used, "persisted_id": persisted_id,
            "requires_approval": spec["tier"] == "impactful"}


@app.post("/pentest/cleanup")
async def cleanup_old_sessions_endpoint(
    older_than_hours: int = Query(default=24, ge=1, description="Delete sessions older than this many hours"),
    statuses: str = Query(
        default="completed,failed,stalled,cancelled",
        description="Comma-separated list of statuses to delete (default: completed,failed,stalled,cancelled)"
    ),
    dry_run: bool = Query(default=False, description="If true, show what would be deleted without actually deleting")
):
    """
    Delete old sessions and their associated data from the database.

    This permanently removes sessions and their messages. Use dry_run=true to preview
    what would be deleted before actually deleting.

    By default, only deletes completed, failed, stalled, and cancelled sessions.
    Active sessions are never deleted unless explicitly included in statuses.
    """
    import sys

    status_list = [s.strip() for s in statuses.split(',') if s.strip()]

    # Validate statuses
    valid_statuses = {'active', 'completed', 'stopped', 'failed', 'stalled', 'cancelled'}
    invalid = set(status_list) - valid_statuses
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid statuses: {invalid}. Valid: {valid_statuses}"
        )

    # Safety check: warn if trying to delete active sessions
    if 'active' in status_list:
        print(f"[CLEANUP] WARNING: Deleting active sessions older than {older_than_hours}h", file=sys.stderr)

    if dry_run:
        # Preview what would be deleted
        sessions = list_agent_sessions(limit=1000)
        cutoff = datetime.utcnow() - timedelta(hours=older_than_hours)

        would_delete = []
        total_messages = 0
        for session in sessions:
            if (session.get('status') in status_list and
                session.get('created_at') and
                session['created_at'].replace(tzinfo=None) < cutoff):
                messages = get_agent_messages(session['id'], limit=10000)
                would_delete.append({
                    "id": str(session['id']),
                    "name": session['session_name'],
                    "status": session['status'],
                    "created_at": session['created_at'].isoformat() if session['created_at'] else None,
                    "messages": len(messages)
                })
                total_messages += len(messages)

        return {
            "dry_run": True,
            "would_delete_count": len(would_delete),
            "would_delete_messages": total_messages,
            "sessions": would_delete,
            "cutoff_time": cutoff.isoformat(),
            "statuses_filter": status_list
        }

    # Actually delete
    result = delete_old_sessions(older_than_hours=older_than_hours, statuses=status_list)

    print(f"[CLEANUP] Deleted {result['deleted_count']} sessions, {result['message_count']} messages", file=sys.stderr)

    return {
        "dry_run": False,
        "deleted_count": result['deleted_count'],
        "deleted_messages": result['message_count'],
        "deleted_sessions": result['deleted_sessions'],
        "cutoff_hours": older_than_hours,
        "statuses_filter": status_list
    }


@app.get("/pentest/{session_id}")
async def get_pentest_status(session_id: str):
    """
    Get status and details of a pentest session
    """
    try:
        session_uuid = uuid.UUID(session_id)
        session = get_agent_session(session_uuid)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        # Get message count
        messages = get_agent_messages(session_uuid)

        # Log status check
        import sys
        print(f"[{session_id}] 📊 Status check: {session['status']} | Messages: {len(messages)} | Session: {session['session_name']}", file=sys.stderr)

        # Surface error reason when session failed
        error_msg = None
        summary = session.get('summary')
        if session['status'] == 'failed' and summary:
            error_msg = summary

        return {
            "session_id": str(session['id']),
            "session_name": session['session_name'],
            "status": session['status'],
            "target_description": session['target_description'],
            "started_at": session['created_at'].isoformat() if session['created_at'] else None,
            "ended_at": session['end_time'].isoformat() if session.get('end_time') else None,
            "message_count": len(messages),
            "summary": summary,
            "error": error_msg,
            "configuration": session.get('configuration', {}),
            "metadata": session.get('metadata', {})
        }

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/pentest/{session_id}/flow-summary")
def get_session_flow_summary(session_id: uuid.UUID):
    """Per-scan-type summary of everything the session ran.

    Served from the live tracker while the session is active, and from the
    persisted copy on agent_sessions.metadata once it has ended.
    """
    live = {}
    try:
        live = scan_tracker.build_flow_summary(str(session_id)) or {}
    except Exception:
        live = {}
    if live.get("total_scans"):
        return {"source": "live", **live}

    row = get_agent_session(session_id)
    if not row:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    stored = ((row.get("metadata") or {}).get("scan_flow_summary")) or {}
    if not stored:
        return {
            "source": "none",
            "session_id": str(session_id),
            "total_scans": 0,
            "detail": "No scan flow recorded — the session ran no scans, or it "
                      "predates flow-summary collection.",
        }
    return {"source": "persisted", **stored}


@app.get("/pentest/{session_id}/messages")
async def get_pentest_messages(
    session_id: str,
    limit: int = 100
):
    """
    Get conversation messages for a pentest session
    """
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    # Retry once on transient DB errors (connection pool exhaustion, etc.)
    last_err = None
    for _attempt in range(2):
        try:
            session = get_agent_session(session_uuid)

            if not session:
                raise HTTPException(status_code=404, detail="Session not found")

            messages = get_agent_messages(session_uuid, limit=limit)

            import sys
            print(f"[{session_id}] 💬 Fetching {len(messages)} messages (limit={limit}) | Session: {session['session_name']}", file=sys.stderr)

            def _ts(val):
                if val is None:
                    return None
                return val.isoformat() if hasattr(val, 'isoformat') else str(val)

            return {
                "session_id": session_id,
                "messages": [
                    {
                        "agent_name": msg['agent_name'],
                        "role": msg['role'],
                        "content": msg['content'],
                        "timestamp": _ts(msg['created_at']),
                        "metadata": msg.get('metadata', {})
                    }
                    for msg in messages
                ]
            }
        except HTTPException:
            raise
        except Exception as e:
            last_err = e
            import time
            time.sleep(0.1)

    session_logger.error(f"[{session_id}] Messages endpoint error: {type(last_err).__name__}: {last_err}")
    raise HTTPException(status_code=500, detail=str(last_err))


@app.get("/pentest/{session_id}/scans")
async def get_pentest_scans(session_id: str):
    """
    Get the status of all scans associated with a pentest session.

    Returns comprehensive scan tracking information including:
    - Session start time
    - Current phase of the pentest
    - Status of all related scans (masscan, nmap, nuclei, web_scan, playwright, udp)
    - Progress information for running scans
    - Summary statistics

    For active sessions, this queries live status from scanner services.
    For completed sessions, returns stored scan metadata.
    """
    import json as json_module

    try:
        session_uuid = uuid.UUID(session_id)
        session = get_agent_session(session_uuid)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        # Log scan status request
        import sys
        print(f"[{session_id}] 📊 Scan status requested | Status: {session['status']} | Session: {session['session_name']}", file=sys.stderr)

        # Check if session is active (has live tracking data)
        if session['status'] == 'active':
            # Get live status from the scan tracker
            status_json = get_session_scan_status(session_id)
            status = json_module.loads(status_json)

            return {
                "session_id": session_id,
                "session_name": session['session_name'],
                "status": session['status'],
                "started_at": session['created_at'].isoformat() if session['created_at'] else None,
                **status
            }
        else:
            # Session is completed/failed - return stored metadata
            metadata = session.get('metadata', {}) or {}
            scans = metadata.get('scans', [])

            # Fallback: if no scans in metadata, check session_scan_metrics table
            if not scans:
                try:
                    from db_utils import get_db
                    from psycopg2.extras import RealDictCursor
                    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute(
                            """SELECT scan_type, job_id, status, started_at, completed_at,
                                      duration_seconds, params, result_summary
                               FROM session_scan_metrics
                               WHERE session_id = %s ORDER BY created_at""",
                            (str(session_uuid),)
                        )
                        for row in cur.fetchall():
                            scans.append({
                                "type": row["scan_type"],
                                "job_id": row.get("job_id", ""),
                                "status": row["status"],
                                "started_at": row["started_at"].isoformat() if row.get("started_at") else None,
                                "completed_at": row["completed_at"].isoformat() if row.get("completed_at") else None,
                                "duration_seconds": float(row["duration_seconds"]) if row.get("duration_seconds") else None,
                                "params": row.get("params", {}),
                                "result_summary": row.get("result_summary"),
                            })
                except Exception as e:
                    session_logger.warning(f"[{session_id}] Failed to query scan metrics fallback: {e}")

            # Reconcile stale "running" statuses by polling scanner services
            stale = [s for s in scans if s.get('status') == 'running']
            if stale:
                import httpx as httpx_client
                import sys
                type_to_url = {
                    "masscan": os.environ.get("NMAP_URL", "https://nmap_scanner:8012"),
                    "nmap": os.environ.get("NMAP_URL", "https://nmap_scanner:8012"),
                    "udp": os.environ.get("NMAP_URL", "https://nmap_scanner:8012"),
                    "full_scan": os.environ.get("NMAP_URL", "https://nmap_scanner:8012"),
                    "smb_vuln": os.environ.get("NMAP_URL", "https://nmap_scanner:8012"),
                    "credential_check": os.environ.get("NMAP_URL", "https://nmap_scanner:8012"),
                    "web_scan": os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010"),
                    "nuclei": os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011"),
                    "httpx": os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023"),
                    "naabu": os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023"),
                    "katana": os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023"),
                    "tlsx": os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023"),
                    "subfinder": os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024"),
                    "dnsx": os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024"),
                    "passive-recon": os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024"),
                    "recon-pipeline": os.environ.get("OSINT_RUNNER_URL", "https://osint-runner:8024"),
                    "brutus": os.environ.get("BRUTUS_RUNNER_URL", "https://brutus-runner:8025"),
                    "playwright": os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014"),
                }
                for scan in stale:
                    svc = type_to_url.get(scan.get('type'))
                    if not svc:
                        print(f"[{session_id}] No service URL for scan type: {scan.get('type')}", file=sys.stderr)
                        continue
                    try:
                        if scan.get('type') == 'playwright':
                            url = f"{svc}/scan/{scan['job_id']}"
                        else:
                            url = f"{svc}/jobs/{scan['job_id']}"
                        r = httpx_client.get(url, timeout=5.0, verify=False)
                        if r.status_code == 200:
                            live = r.json()
                            scan['status'] = live.get('status', scan['status'])
                            if live.get('completed_at'):
                                scan['completed_at'] = live['completed_at']
                            if live.get('error'):
                                scan['error'] = live['error']
                        elif r.status_code == 404:
                            # Job expired from scanner memory — session is done,
                            # so the scan must have finished (completed or failed)
                            scan['status'] = 'completed'
                    except Exception as e:
                        print(f"[{session_id}] Failed to poll {scan.get('type')} {scan['job_id']}: {e}", file=sys.stderr)

            scan_summary = {
                "total_scans": len(scans),
                "completed": sum(1 for s in scans if s.get('status') == 'completed'),
                "running": sum(1 for s in scans if s.get('status') == 'running'),
                "failed": sum(1 for s in scans if s.get('status') == 'failed'),
            }

            return {
                "session_id": session_id,
                "session_name": session['session_name'],
                "status": session['status'],
                "started_at": session['created_at'].isoformat() if session['created_at'] else None,
                "ended_at": session.get('end_time').isoformat() if session.get('end_time') else None,
                "scans": scans,
                "summary": scan_summary,
            }

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/pentest/{session_id}/report")
async def get_pentest_report(session_id: str):
    """
    Get the final report for a completed pentest session
    Looks for the Reporter agent's final message
    """
    try:
        session_uuid = uuid.UUID(session_id)
        session = get_agent_session(session_uuid)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        # Log report request
        import sys
        print(f"[{session_id}] 📄 Report requested | Status: {session['status']} | Session: {session['session_name']}", file=sys.stderr)

        if session['status'] != 'completed':
            raise HTTPException(
                status_code=400,
                detail=f"Session is not completed yet. Current status: {session['status']}"
            )

        # Get all messages and find Reporter's messages
        messages = get_agent_messages(session_uuid, limit=1000)

        reporter_messages = [
            msg for msg in messages
            if msg['agent_name'] == 'Reporter'
        ]

        if not reporter_messages:
            return {
                "session_id": session_id,
                "report": session.get('summary', 'No report available yet.'),
                "generated_at": session.get('end_time')
            }

        # Get the last reporter message as the final report
        final_report = reporter_messages[-1]['content']

        return {
            "session_id": session_id,
            "session_name": session['session_name'],
            "target_description": session['target_description'],
            "report": final_report,
            "generated_at": reporter_messages[-1]['created_at'].isoformat(),
            "status": session['status']
        }

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sessions")
async def list_sessions(
    status: Optional[str] = None,
    limit: int = 50
):
    """
    List all pentest sessions with optional status filter

    Args:
        status: Filter by status (active, completed, failed)
        limit: Maximum number of sessions to return
    """
    try:
        sessions = list_agent_sessions(status=status, limit=limit)

        return {
            "sessions": [
                {
                    "session_id": str(s['id']),
                    "session_name": s['session_name'],
                    "status": s['status'],
                    "target_description": s['target_description'],
                    "created_at": s['created_at'].isoformat() if s['created_at'] else None,
                    "end_time": s['end_time'].isoformat() if s.get('end_time') else None,
                }
                for s in sessions
            ],
            "total": len(sessions)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pentest/{session_id}/stop")
async def stop_pentest(session_id: str):
    """
    Stop an active pentest session
    """
    try:
        session_uuid = uuid.UUID(session_id)
        session = get_agent_session(session_uuid)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        if session['status'] != 'active':
            raise HTTPException(
                status_code=400,
                detail=f"Session is not active. Current status: {session['status']}"
            )

        # Persist scan data before stopping
        scan_status = scan_tracker.get_session_status(session_id)
        scans_metadata = scan_status.get("scans", []) if isinstance(scan_status, dict) else []
        scan_tracker.persist_to_db(session_id)

        # Update session status with scan metadata
        update_agent_session(
            session_id=session_uuid,
            status="stopped",
            summary="Session stopped by user",
            metadata={
                "scans": scans_metadata,
                "scan_summary": scan_status.get("summary") if isinstance(scan_status, dict) else None,
            }
        )

        # Cleanup tracker and remove from active sessions
        scan_tracker.clear_session()
        scan_tracker.cleanup_session(session_id)
        if session_id in active_sessions:
            del active_sessions[session_id]

        return {
            "session_id": session_id,
            "status": "stopped",
            "message": "Session stopped successfully"
        }

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/pentest/{session_id}")
async def delete_session_endpoint(session_id: str):
    """Delete a pentest session and its messages (cannot delete active sessions)"""
    try:
        session_uuid = uuid.UUID(session_id)
        session = get_agent_session(session_uuid)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        if session.get("status") == "active":
            raise HTTPException(
                status_code=400,
                detail="Cannot delete active session — stop it first"
            )

        # Remove from in-memory trackers
        scan_tracker._registry.pop(session_id, None)
        if session_id in active_sessions:
            del active_sessions[session_id]

        delete_agent_session(session_uuid)
        return {"ok": True, "session_id": session_id}

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# `POST /pentest/{id}/nudge` was here. It reset the watchdog timer so a stalled
# GroupChat could be given more time. Retired with AutoGen: a StateGraph either
# is executing a node or is parked on an interrupt, and the durable answer to
# "keep going" is POST /pentest/{id}/approve, which resumes from the Postgres
# checkpoint. Nothing called it — the BFF declared no proxy and the frontend had
# no hook, so removing it breaks no caller.


@app.get("/pentest/{session_id}/pending-approval")
async def get_session_pending_approval(session_id: str):
    """What a LangGraph session is paused on, read from its Postgres checkpoint.

    Answers from the checkpoint rather than in-process state, so it is correct
    even after a restart — which is the whole point of the durable checkpointer.
    """
    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = get_agent_session(session_uuid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        from langgraph_engine import get_pending_approval
    except Exception as e:  # noqa: BLE001
        # Surfaced, not swallowed: a missing langgraph install must not read as
        # "nothing is pending" on a session that is genuinely parked.
        raise HTTPException(
            status_code=503,
            detail=f"LangGraph engine unavailable, cannot read the checkpoint: {e}")

    pending = get_pending_approval(session_uuid)
    return {
        "session_id": session_id,
        "status": session.get("status"),
        "engine": (session.get("configuration") or {}).get("engine"),
        "awaiting_approval": bool(pending),
        "pending": pending,
        "answer_with": f"POST /pentest/{session_id}/approve",
    }


@app.post("/pentest/{session_id}/approve")
async def approve_session_step(session_id: str, request: ApprovalRequest):
    """Answer a paused LangGraph approval interrupt and continue the SAME session.

    This is the operator's authorization, so there is no override: a session that
    is not actually parked cannot be "approved" into running an exploit, and an
    approval carrying no pending_exploit_id executes nothing. `Command(resume=…)`
    continues the graph from its Postgres checkpoint — no new session row, no
    replay of the phases already done.
    """
    import asyncio

    try:
        session_uuid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")

    session = get_agent_session(session_uuid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    try:
        from langgraph_engine import get_pending_approval, resume_langgraph_session_sync
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"LangGraph engine unavailable: {e}")

    pending = get_pending_approval(session_uuid)
    if not pending:
        raise HTTPException(
            status_code=409,
            detail=f"Session {session_id} is not paused on an approval "
                   f"(status='{session.get('status')}'). Nothing to approve.")

    if request.approved and not request.pending_exploit_id:
        # Fail loudly rather than resuming into a no-op the operator would read
        # as "approved and executed".
        raise HTTPException(
            status_code=400,
            detail="approved=true requires pending_exploit_id (the pending_exploits "
                   "row to execute). List candidates with GET /api/exploits/pending.")

    session_logger.info(
        "[%s] Operator approval: approved=%s pending_exploit_id=%s",
        session_id, request.approved, request.pending_exploit_id)

    asyncio.create_task(
        asyncio.to_thread(
            resume_langgraph_session_sync,
            session_uuid,
            bool(request.approved),
            request.pending_exploit_id,
            request.note,
        )
    )

    return {
        "session_id": session_id,
        "approved": bool(request.approved),
        "pending_exploit_id": request.pending_exploit_id,
        "status": "resuming",
        "message": ("Approved — resuming from the Postgres checkpoint and executing "
                    "the approved exploit." if request.approved else
                    "Declined — resuming from the Postgres checkpoint straight to the report."),
    }


# Log Viewing Endpoints
@app.get("/logs")
async def get_logs(
    level: Optional[str] = Query(None, description="Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"),
    limit: int = Query(100, description="Maximum number of log records to return", ge=1, le=1000),
    search: Optional[str] = Query(None, description="Search term in log messages"),
    request_id: Optional[str] = Query(None, description="Filter by request ID")
):
    """
    Get diagnostic logs with optional filtering

    Query Parameters:
    - level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - limit: Maximum number of records (1-1000, default 100)
    - search: Search term in log messages
    - request_id: Filter by request ID

    Returns list of log records with timestamp, level, message, etc.
    """
    try:
        handler = get_log_handler()
        logs = handler.get_logs(
            level=level,
            limit=limit,
            search=search,
            request_id=request_id
        )

        return {
            "logs": logs,
            "count": len(logs),
            "filters": {
                "level": level,
                "limit": limit,
                "search": search,
                "request_id": request_id
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")


@app.get("/logs/stats")
async def get_log_stats():
    """
    Get logging statistics

    Returns statistics about log collection including:
    - Total logs received
    - Breakdown by log level
    - Current buffer size
    - Collection start time
    """
    try:
        handler = get_log_handler()
        stats = handler.get_stats()

        return {
            "ok": True,
            "stats": stats
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve stats: {str(e)}")


@app.delete("/logs")
async def clear_logs():
    """
    Clear all logs from the buffer

    Useful for starting fresh debugging sessions.
    Statistics counters will also be reset.
    """
    try:
        handler = get_log_handler()
        handler.clear()

        return {
            "ok": True,
            "message": "All logs cleared successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear logs: {str(e)}")


class ExternalLogEntry(BaseModel):
    """Log entry from external source (MCP servers, etc.)"""
    level: str = Field(..., description="Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    message: str = Field(..., description="Log message")
    source: str = Field(default="external", description="Source identifier (e.g., 'mcp-health-check')")
    request_id: Optional[str] = Field(None, description="Optional request ID for correlation")


@app.post("/logs/ingest")
async def ingest_log(entry: ExternalLogEntry):
    """
    Ingest a log entry from an external source (MCP servers, CLI tools, etc.)

    This allows external processes to send logs to the central log viewer.
    Useful for MCP servers running outside the container to log their activity.
    """
    try:
        # Get the log handler and add the log directly to avoid logger deadlocks
        handler = get_log_handler()

        # Format message with request_id if present
        message = entry.message
        if entry.request_id:
            message = f"[{entry.request_id}] {message}"

        # Create a minimal LogRecord manually to avoid uvicorn logging deadlock
        import logging
        record = logging.LogRecord(
            name=f"external.{entry.source}",
            level=getattr(logging, entry.level.upper(), logging.INFO),
            pathname="<external>",
            lineno=0,
            msg=message,
            args=(),
            exc_info=None
        )
        record.funcName = entry.source
        record.module = "external"

        # Emit directly to handler (bypasses logger hierarchy)
        handler.emit(record)

        return {"ok": True, "message": "Log ingested successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to ingest log: {str(e)}")


@app.get("/logs/export", response_class=PlainTextResponse)
async def export_logs():
    """
    Export all logs as JSON file

    Downloads all logs in the buffer as a formatted JSON file
    including statistics and metadata.
    """
    try:
        handler = get_log_handler()
        json_export = handler.export_json()

        return PlainTextResponse(
            content=json_export,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=scan_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            }
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to export logs: {str(e)}")


@app.get("/logs/test")
async def test_logs():
    """
    Generate sample logs for testing the log viewing interface

    Creates various log levels to demonstrate the web interface functionality.
    """
    import logging
    from datetime import datetime

    # Get handler and directly create test log records
    handler = get_log_handler()

    # Create mock LogRecord objects and emit them directly
    # This bypasses potential logging configuration issues
    test_logs = [
        ("INFO", "[test_operation_1697389520000] Starting: Test scan of 192.168.1.1"),
        ("INFO", "[test_operation_1697389520000] Success: Test scan completed"),
        ("INFO", "[query_assets_1697389521000] Starting: Query assets (limit=10)"),
        ("WARNING", "[query_assets_1697389521000] Warning: Large dataset detected"),
        ("INFO", "[query_assets_1697389521000] Success: Query assets completed"),
        ("INFO", "[nmap_scan_1697389522000] Starting: Nmap scan of 10.0.0.1"),
        ("ERROR", "[nmap_scan_1697389522000] Failed: HTTP 404 - Nmap scanner endpoint not found"),
        ("INFO", "[playwright_scan_1697389523000] Starting: Playwright scan of http://example.com"),
        ("ERROR", "[playwright_scan_1697389523000] JSON parse error: Invalid response from scanner"),
        ("INFO", "[masscan_scan_1697389524000] Starting: Masscan of 192.168.1.0/24"),
        ("INFO", "[masscan_scan_1697389524000] Success: Masscan completed"),
    ]

    # Create and emit log records
    for level, message in test_logs:
        record = logging.LogRecord(
            name="scan_tools",
            level=logging.getLevelName(level),
            pathname="test",
            lineno=0,
            msg=message,
            args=(),
            exc_info=None
        )
        record.levelname = level
        handler.emit(record)

    # Return summary
    stats = handler.get_stats()

    return {
        "ok": True,
        "message": f"Generated {len(test_logs)} sample log entries",
        "stats": stats,
        "hint": "Visit /logs/ui to view the logs in the web interface"
    }


@app.get("/logs/ui", response_class=HTMLResponse)
async def logs_ui():
    """
    Web interface for viewing diagnostic logs

    Interactive HTML interface with:
    - Real-time log viewing
    - Filtering by level, search, request ID
    - Statistics display
    - Export functionality
    - Auto-refresh option
    """
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Tools Diagnostic Logs</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }

        h1 {
            color: white;
            font-size: 28px;
            margin-bottom: 10px;
        }

        .subtitle {
            color: rgba(255, 255, 255, 0.9);
            font-size: 14px;
        }

        .controls {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }

        .control-group {
            display: flex;
            flex-direction: column;
        }

        label {
            font-size: 12px;
            color: #aaa;
            margin-bottom: 5px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        input, select {
            background: #1a1a1a;
            border: 1px solid #444;
            color: #e0e0e0;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
        }

        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }

        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
        }

        button:hover {
            background: #5568d3;
            transform: translateY(-1px);
        }

        button.secondary {
            background: #444;
        }

        button.secondary:hover {
            background: #555;
        }

        button.danger {
            background: #dc3545;
        }

        button.danger:hover {
            background: #c82333;
        }

        .stats {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }

        .stat-card {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }

        .stat-label {
            font-size: 12px;
            color: #aaa;
            margin-bottom: 5px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #fff;
        }

        .logs-container {
            background: #2a2a2a;
            border-radius: 10px;
            padding: 20px;
            min-height: 400px;
            max-height: 600px;
            overflow-y: auto;
        }

        .log-entry {
            background: #1a1a1a;
            margin-bottom: 10px;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .log-entry.DEBUG { border-left-color: #6c757d; }
        .log-entry.INFO { border-left-color: #28a745; }
        .log-entry.WARNING { border-left-color: #ffc107; }
        .log-entry.ERROR { border-left-color: #dc3545; }
        .log-entry.CRITICAL { border-left-color: #e83e8c; }

        .log-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .log-level {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }

        .log-level.DEBUG { background: #6c757d; color: white; }
        .log-level.INFO { background: #28a745; color: white; }
        .log-level.WARNING { background: #ffc107; color: black; }
        .log-level.ERROR { background: #dc3545; color: white; }
        .log-level.CRITICAL { background: #e83e8c; color: white; }

        .log-time {
            color: #aaa;
            font-size: 11px;
        }

        .log-message {
            color: #e0e0e0;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .log-meta {
            margin-top: 8px;
            font-size: 11px;
            color: #888;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #aaa;
        }

        .error-message {
            background: #dc3545;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .button-group {
            display: flex;
            gap: 10px;
            grid-column: span 2;
        }

        .auto-refresh {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .auto-refresh input[type="checkbox"] {
            width: auto;
        }

        @media (max-width: 768px) {
            .controls {
                grid-template-columns: 1fr;
            }

            .button-group {
                grid-column: span 1;
            }

            .stats {
                grid-template-columns: repeat(2, 1fr);
            }

            .health-services {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        /* Health Panel Styles */
        .health-panel {
            background: #2a2a2a;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }

        .health-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .health-header h2 {
            color: #e0e0e0;
            font-size: 18px;
            margin: 0;
        }

        .health-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .health-summary-card {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }

        .health-summary-card.healthy {
            border-left: 4px solid #28a745;
        }

        .health-summary-card.degraded {
            border-left: 4px solid #fd7e14;
        }

        .health-summary-card.unhealthy {
            border-left: 4px solid #dc3545;
        }

        .health-summary-card.error {
            border-left: 4px solid #6c757d;
        }

        .health-summary-label {
            font-size: 11px;
            color: #aaa;
            text-transform: uppercase;
            margin-bottom: 5px;
        }

        .health-summary-value {
            font-size: 20px;
            font-weight: bold;
        }

        .health-summary-value.healthy { color: #28a745; }
        .health-summary-value.degraded { color: #fd7e14; }
        .health-summary-value.unhealthy { color: #dc3545; }
        .health-summary-value.error { color: #6c757d; }

        .health-services {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
        }

        .service-card {
            background: #1a1a1a;
            padding: 12px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .service-icon {
            font-size: 16px;
        }

        .service-icon.pass { color: #28a745; }
        .service-icon.warn { color: #ffc107; }
        .service-icon.fail { color: #dc3545; }

        .service-info {
            flex: 1;
            min-width: 0;
        }

        .service-name {
            font-size: 13px;
            font-weight: 600;
            color: #e0e0e0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .service-message {
            font-size: 11px;
            color: #888;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .health-loading {
            text-align: center;
            padding: 20px;
            color: #aaa;
        }

        .health-error {
            background: rgba(220, 53, 69, 0.2);
            border: 1px solid #dc3545;
            border-radius: 5px;
            padding: 15px;
            color: #dc3545;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Scan Tools Diagnostic Logs</h1>
            <p class="subtitle">Real-time monitoring of scan_tools.py operations</p>
        </header>

        <div class="health-panel" id="health-panel">
            <div class="health-header">
                <h2>System Health</h2>
                <button onclick="loadHealth()" class="secondary">Refresh Status</button>
            </div>
            <div id="health-content">
                <div class="health-loading">Loading system health...</div>
            </div>
        </div>

        <div class="stats" id="stats">
            <div class="stat-card">
                <div class="stat-label">Total Logs</div>
                <div class="stat-value" id="stat-total">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Errors</div>
                <div class="stat-value" id="stat-errors" style="color: #dc3545;">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Info</div>
                <div class="stat-value" id="stat-info" style="color: #28a745;">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Debug</div>
                <div class="stat-value" id="stat-debug" style="color: #6c757d;">-</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Buffer Size</div>
                <div class="stat-value" id="stat-buffer">-</div>
            </div>
        </div>

        <div class="controls">
            <div class="control-group">
                <label for="level">Log Level</label>
                <select id="level">
                    <option value="">All Levels</option>
                    <option value="DEBUG">DEBUG</option>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="ERROR">ERROR</option>
                    <option value="CRITICAL">CRITICAL</option>
                </select>
            </div>

            <div class="control-group">
                <label for="search">Search Message</label>
                <input type="text" id="search" placeholder="Search in messages...">
            </div>

            <div class="control-group">
                <label for="request-id">Request ID</label>
                <input type="text" id="request-id" placeholder="Filter by request ID...">
            </div>

            <div class="control-group">
                <label for="limit">Limit</label>
                <select id="limit">
                    <option value="50">50 logs</option>
                    <option value="100" selected>100 logs</option>
                    <option value="200">200 logs</option>
                    <option value="500">500 logs</option>
                    <option value="1000">1000 logs</option>
                </select>
            </div>

            <div class="button-group">
                <button onclick="loadLogs()">🔄 Refresh</button>
                <button onclick="exportLogs()" class="secondary">📥 Export JSON</button>
                <button onclick="clearLogs()" class="danger">🗑️ Clear Logs</button>
            </div>

            <div class="auto-refresh">
                <input type="checkbox" id="auto-refresh" onchange="toggleAutoRefresh()">
                <label for="auto-refresh" style="text-transform: none; margin: 0;">Auto-refresh (5s)</label>
            </div>
        </div>

        <div class="logs-container" id="logs">
            <div class="loading">Loading logs...</div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;

        async function loadStats() {
            try {
                const response = await fetch('/logs/stats');
                const data = await response.json();

                if (data.ok && data.stats) {
                    document.getElementById('stat-total').textContent = data.stats.total_received.toLocaleString();
                    document.getElementById('stat-errors').textContent = data.stats.by_level.ERROR.toLocaleString();
                    document.getElementById('stat-info').textContent = data.stats.by_level.INFO.toLocaleString();
                    document.getElementById('stat-debug').textContent = data.stats.by_level.DEBUG.toLocaleString();
                    document.getElementById('stat-buffer').textContent = (
                        `${data.stats.current_buffer_size}/${data.stats.max_buffer_size}`
                    );
                }
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        async function loadLogs() {
            const level = document.getElementById('level').value;
            const search = document.getElementById('search').value;
            const requestId = document.getElementById('request-id').value;
            const limit = document.getElementById('limit').value;

            const params = new URLSearchParams();
            if (level) params.append('level', level);
            if (search) params.append('search', search);
            if (requestId) params.append('request_id', requestId);
            params.append('limit', limit);

            try {
                const response = await fetch(`/logs?${params}`);
                const data = await response.json();

                const logsContainer = document.getElementById('logs');

                if (data.logs.length === 0) {
                    logsContainer.innerHTML = '<div class="loading">No logs found matching filters</div>';
                    return;
                }

                logsContainer.innerHTML = data.logs.map(log => `
                    <div class="log-entry ${log.level}">
                        <div class="log-header">
                            <span class="log-level ${log.level}">${log.level}</span>
                            <span class="log-time">${new Date(log.timestamp).toLocaleString()}</span>
                        </div>
                        <div class="log-message">${escapeHtml(log.message)}</div>
                        <div class="log-meta">
                            ${log.request_id ? `Request ID: ${log.request_id} | ` : ''}
                            ${log.module}.${log.function}:${log.line}
                        </div>
                    </div>
                `).join('');

                // Auto-scroll to bottom
                logsContainer.scrollTop = logsContainer.scrollHeight;

                // Also load stats
                await loadStats();

            } catch (error) {
                document.getElementById('logs').innerHTML = `
                    <div class="error-message">
                        Failed to load logs: ${error.message}
                    </div>
                `;
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        async function exportLogs() {
            try {
                const response = await fetch('/logs/export');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `scan_logs_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            } catch (error) {
                alert('Failed to export logs: ' + error.message);
            }
        }

        async function clearLogs() {
            if (!confirm('Are you sure you want to clear all logs? This cannot be undone.')) {
                return;
            }

            try {
                const response = await fetch('/logs', { method: 'DELETE' });
                const data = await response.json();

                if (data.ok) {
                    alert('Logs cleared successfully');
                    loadLogs();
                }
            } catch (error) {
                alert('Failed to clear logs: ' + error.message);
            }
        }

        function toggleAutoRefresh() {
            const checkbox = document.getElementById('auto-refresh');

            if (checkbox.checked) {
                autoRefreshInterval = setInterval(loadLogs, 5000);
            } else {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
        }

        // Event listeners for filter changes
        document.getElementById('level').addEventListener('change', loadLogs);
        document.getElementById('search').addEventListener('input', debounce(loadLogs, 500));
        document.getElementById('request-id').addEventListener('input', debounce(loadLogs, 500));
        document.getElementById('limit').addEventListener('change', loadLogs);

        function debounce(func, wait) {
            let timeout;
            return function executedFunction(...args) {
                const later = () => {
                    clearTimeout(timeout);
                    func(...args);
                };
                clearTimeout(timeout);
                timeout = setTimeout(later, wait);
            };
        }

        // Health check functions
        async function loadHealth() {
            const healthContent = document.getElementById('health-content');
            healthContent.innerHTML = '<div class="health-loading">Loading system health...</div>';

            try {
                const response = await fetch('/health/system');
                const data = await response.json();

                if (data.status === 'error') {
                    healthContent.innerHTML = `
                        <div class="health-error">
                            Unable to fetch health status: ${escapeHtml(data.message)}
                        </div>
                    `;
                    return;
                }

                const statusClass = data.status || 'error';
                const statusIcon = {
                    'healthy': '✅',
                    'degraded': '⚠️',
                    'unhealthy': '❌',
                    'error': '❓'
                }[statusClass] || '❓';

                const readyIcon = data.ready_for_operations ? '✅' : '❌';
                const summary = data.summary || {};

                let html = `
                    <div class="health-summary">
                        <div class="health-summary-card ${statusClass}">
                            <div class="health-summary-label">Status</div>
                            <div class="health-summary-value ${statusClass}">${statusIcon} ${(data.status || 'Unknown').toUpperCase()}</div>
                        </div>
                        <div class="health-summary-card ${statusClass}">
                            <div class="health-summary-label">Health Score</div>
                            <div class="health-summary-value ${statusClass}">${summary.health_percentage || 0}%</div>
                        </div>
                        <div class="health-summary-card ${data.ready_for_operations ? 'healthy' : 'unhealthy'}">
                            <div class="health-summary-label">Ready</div>
                            <div class="health-summary-value ${data.ready_for_operations ? 'healthy' : 'unhealthy'}">${readyIcon} ${data.ready_for_operations ? 'Yes' : 'No'}</div>
                        </div>
                        <div class="health-summary-card ${statusClass}">
                            <div class="health-summary-label">Checks</div>
                            <div class="health-summary-value">${summary.passed || 0}/${summary.total || 0}</div>
                        </div>
                    </div>
                `;

                if (data.checks && data.checks.length > 0) {
                    html += '<div class="health-services">';
                    for (const check of data.checks) {
                        const icon = {
                            'pass': '✅',
                            'warn': '⚠️',
                            'fail': '❌'
                        }[check.status] || '❓';

                        // Extract service name from check name
                        const serviceName = check.check.replace('Service: ', '');

                        html += `
                            <div class="service-card">
                                <span class="service-icon ${check.status}">${icon}</span>
                                <div class="service-info">
                                    <div class="service-name">${escapeHtml(serviceName)}</div>
                                    <div class="service-message">${escapeHtml(check.message)}</div>
                                </div>
                            </div>
                        `;
                    }
                    html += '</div>';
                }

                healthContent.innerHTML = html;

            } catch (error) {
                healthContent.innerHTML = `
                    <div class="health-error">
                        Failed to load health status: ${escapeHtml(error.message)}
                    </div>
                `;
            }
        }

        // Load logs on page load
        loadLogs();
        // Load health status on page load (manual refresh only after initial load)
        loadHealth();
    </script>
</body>
</html>
    """

    return HTMLResponse(content=html_content)


@app.get("/exploit-watcher/status")
async def get_exploit_watcher_status():
    """
    Get exploit watcher status and configuration.

    Returns information about:
    - Whether the watcher is enabled and running
    - Configuration (poll interval, confidence threshold, etc.)
    - Number of vulnerabilities processed
    """
    watcher = get_exploit_watcher()
    status = await watcher.get_status()
    status["enabled"] = EXPLOIT_WATCHER_ENABLED
    return status


@app.post("/exploit-watcher/stop")
async def stop_exploit_watcher_endpoint():
    """
    Stop the exploit watcher background task.
    """
    watcher = get_exploit_watcher()
    if not watcher.running:
        raise HTTPException(status_code=400, detail="Exploit watcher is not running")

    watcher.stop()
    return {"message": "Exploit watcher stopped", "status": "stopped"}


@app.post("/exploit-watcher/start")
async def start_exploit_watcher_endpoint():
    """
    Start the exploit watcher if it's not running.
    """
    import asyncio

    watcher = get_exploit_watcher()
    if watcher.running:
        raise HTTPException(status_code=400, detail="Exploit watcher is already running")

    asyncio.create_task(start_exploit_watcher())
    return {"message": "Exploit watcher started", "status": "running"}


# --- Report Endpoints ---

@app.get("/reports/summary", response_model=ReportSummaryResponse)
async def get_report_summary(target: Optional[str] = None):
    """
    Get executive summary of security scans.

    Returns aggregated statistics including:
    - Tools executed with success/failure counts
    - Ports discovered with service information
    - Findings grouped by severity
    - Scan time period

    Parameters:
        target: Optional target IP/hostname to filter by
    """
    try:
        summary = db_get_report_summary(target)

        return ReportSummaryResponse(
            target=summary.get("target"),
            scan_period=ScanPeriod(
                started=summary["scan_period"]["started"],
                ended=summary["scan_period"]["ended"]
            ),
            tools_summary=[
                ToolExecutionSummary(**t) for t in summary.get("tools_summary", [])
            ],
            ports_discovered=[
                PortSummary(**p) for p in summary.get("ports_discovered", [])
            ],
            findings_by_severity=summary.get("findings_by_severity", {})
        )
    except Exception as e:
        session_logger.error(f"Failed to get report summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate summary: {e}")


@app.get("/reports/vulnerabilities", response_model=VulnerabilitiesResponse)
async def get_vulnerabilities_report(
    target: Optional[str] = None,
    severity: Optional[str] = None,
    tool: Optional[str] = None
):
    """
    Get vulnerabilities grouped by severity level.

    Returns findings categorized as:
    - critical: Remote code execution, backdoors, unauthenticated access
    - high: SQL injection, credential disclosure, weak passwords
    - medium: Weak ciphers, misconfigurations, outdated software
    - low: Missing headers, minor issues
    - info: Open ports, service versions, enumeration results

    Parameters:
        target: Optional target IP/hostname to filter by
        severity: Optional severity level to filter (critical, high, medium, low, info)
        tool: Optional tool name to filter by
    """
    # Validate severity if provided
    if severity and severity.lower() not in SEVERITY_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    try:
        vulnerabilities = db_get_vulnerabilities_by_severity(
            target=target,
            severity_filter=severity.lower() if severity else None,
            tool_filter=tool
        )

        return VulnerabilitiesResponse(
            target=target,
            vulnerabilities={
                sev: [VulnerabilityEntry(**v) for v in vulns]
                for sev, vulns in vulnerabilities.items()
            }
        )
    except Exception as e:
        session_logger.error(f"Failed to get vulnerabilities report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")


@app.get("/reports/tools", response_model=ToolResultsResponse)
async def get_tool_results(
    target: Optional[str] = None,
    tool: Optional[str] = None,
    include_raw: bool = Query(False, description="Include full raw output in results"),
    status: Optional[str] = Query(None, description="Filter by status (completed/failed/timeout)")
):
    """
    Get detailed results from each tool execution.

    Returns what each tool found during scanning, including:
    - Command that was run
    - Key findings (ports, services, vulnerabilities, credentials)
    - Duration and timestamps
    - Severity classification
    - Execution status (completed/failed/timeout)

    Parameters:
        target: Optional target IP/hostname to filter by
        tool: Optional tool name to filter by
        include_raw: If true, include full raw output for pentester review
        status: Filter by execution status (completed/failed/timeout)
    """
    try:
        results = db_get_tool_results(
            target=target,
            include_raw=include_raw,
            status_filter=status
        )

        # Filter by tool if specified
        if tool:
            results = [r for r in results if r["tool"].lower() == tool.lower()]

        return ToolResultsResponse(
            target=target,
            results=[ToolResult(**r) for r in results],
            total=len(results)
        )
    except Exception as e:
        session_logger.error(f"Failed to get tool results: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get tool results: {e}")


@app.get("/reports/tools/export", response_class=PlainTextResponse)
async def export_tool_results(
    target: Optional[str] = Query(None, description="Filter by target IP/hostname"),
    format: str = Query("markdown", description="Output format: 'markdown' or 'text'"),
    status: Optional[str] = Query(None, description="Filter by status (completed/failed/timeout)")
):
    """
    Export tool execution results as a downloadable pentester report.

    Generates a comprehensive report with:
    - Execution summary table (tool, target, status, exit code, duration)
    - Full raw output for each tool execution
    - Error output when available
    - Findings summary for each execution

    Parameters:
        target: Optional target IP/hostname to filter by
        format: Output format - 'markdown' (default) or 'text'
        status: Filter by execution status (completed/failed/timeout)

    Returns:
        Plain text response with the formatted report
    """
    try:
        # Get results with raw output included
        results = db_get_tool_results(
            target=target,
            include_raw=True,
            status_filter=status
        )

        if format == "text":
            report = generate_pentester_text_report(results, target)
            media_type = "text/plain"
        else:
            report = generate_pentester_markdown_report(results, target)
            media_type = "text/markdown"

        return PlainTextResponse(
            content=report,
            media_type=media_type,
            headers={
                "Content-Disposition": f"attachment; filename=pentest_report.{'txt' if format == 'text' else 'md'}"
            }
        )
    except Exception as e:
        session_logger.error(f"Failed to export tool results: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export tool results: {e}")


@app.get("/reports/vulnerability/{vuln_id}", response_model=VulnerabilityDetailResponse)
async def get_vulnerability_detail(vuln_id: str):
    """
    Get full detail for one vulnerability.

    Returns comprehensive information including:
    - Raw tool output
    - Parsed results
    - Exploit links from RAG search
    - Reproduction steps and command
    - Remediation advice (if available)

    Parameters:
        vuln_id: The execution ID of the vulnerability finding
    """
    try:
        detail = db_get_vulnerability_detail(vuln_id)

        if not detail:
            raise HTTPException(status_code=404, detail="Vulnerability not found")

        # Fetch exploit links asynchronously
        exploit_links = []
        cves = detail.get("cve", [])
        service = detail.get("service")
        parsed = detail.get("parsed_results", {})

        # Get version info if available
        version = None
        services = parsed.get("services", [])
        if services:
            version = services[0].get("version")

        # Try to get exploit links for each CVE and for the service
        if cves:
            for cve in cves[:3]:  # Limit to first 3 CVEs
                links = await get_exploit_links(cve=cve, service=service, version=version)
                exploit_links.extend(links)
        elif service:
            links = await get_exploit_links(service=service, version=version)
            exploit_links.extend(links)

        # Deduplicate exploit links by name
        seen_names = set()
        unique_links = []
        for link in exploit_links:
            if link.get("name") not in seen_names:
                seen_names.add(link.get("name"))
                unique_links.append(ExploitLink(
                    name=link.get("name", "Unknown"),
                    type=link.get("type", "reference"),
                    source=link.get("source"),
                    module=link.get("module"),
                    url=link.get("url"),
                    edb_id=link.get("edb_id"),
                    description=link.get("description")
                ))

        return VulnerabilityDetailResponse(
            id=detail["id"],
            severity=detail["severity"],
            title=detail["title"],
            tool=detail["tool"],
            command=detail["command"],
            target=detail["target"],
            port=detail.get("port"),
            service=detail.get("service"),
            raw_output=detail["raw_output"],
            error_output=detail.get("error_output"),
            parsed_results=detail["parsed_results"],
            cve=detail.get("cve", []),
            exploit_links=unique_links,
            reproduction_steps=detail.get("reproduction_steps", []),
            reproduction_command=detail["reproduction_command"],
            remediation=detail.get("remediation"),
            started_at=detail.get("started_at"),
            completed_at=detail.get("completed_at")
        )
    except HTTPException:
        raise
    except Exception as e:
        session_logger.error(f"Failed to get vulnerability detail: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get vulnerability: {e}")


@app.get("/reports/full")
async def get_full_report(
    target: str = None,
    format: str = "json",
    scope_name: str = None,
):
    """
    Get complete security scan report.

    Combines executive summary and all vulnerabilities into a single report.
    Supports multiple output formats.

    Parameters:
        target: Target IP/hostname (required)
        format: Output format - json (default), html, or markdown

    Returns:
        For json: Structured report data
        For html: HTML rendered report
        For markdown: Markdown formatted report
    """
    # Validate format
    valid_formats = ["json", "html", "markdown"]
    if format.lower() not in valid_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format. Must be one of: {', '.join(valid_formats)}"
        )

    try:
        report = generate_full_report(target, format.lower())

        # For HTML format, render using Jinja2 template
        if format.lower() == "html":
            from jinja2 import Environment, FileSystemLoader

            template_dir = os.path.join(os.path.dirname(__file__), "templates")
            env = Environment(loader=FileSystemLoader(template_dir))

            try:
                template = env.get_template("report.html")
                html_content = template.render(
                    target=target,
                    generated_at=report["generated_at"],
                    summary=report["summary"],
                    vulnerabilities=report["vulnerabilities"],
                    severity_levels=SEVERITY_LEVELS
                )
                return HTMLResponse(content=html_content)
            except Exception as template_error:
                session_logger.warning(f"Template rendering failed: {template_error}, returning JSON")
                # Fall back to JSON if template fails
                pass

        # Convert summary to response model format
        summary_data = report["summary"]
        formatted_summary = ReportSummaryResponse(
            target=summary_data.get("target"),
            scan_period=ScanPeriod(
                started=summary_data["scan_period"]["started"],
                ended=summary_data["scan_period"]["ended"]
            ),
            tools_summary=[
                ToolExecutionSummary(**t) for t in summary_data.get("tools_summary", [])
            ],
            ports_discovered=[
                PortSummary(**p) for p in summary_data.get("ports_discovered", [])
            ],
            findings_by_severity=summary_data.get("findings_by_severity", {})
        )

        # Convert vulnerabilities to response model format
        formatted_vulns = {
            sev: [VulnerabilityEntry(**v) for v in vulns]
            for sev, vulns in report["vulnerabilities"].items()
        }

        return FullReportResponse(
            target=target,
            generated_at=report["generated_at"],
            format=format.lower(),
            summary=formatted_summary,
            vulnerabilities=formatted_vulns,
            rendered=report.get("rendered")  # Markdown content if format=markdown
        )
    except Exception as e:
        session_logger.error(f"Failed to generate full report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")


# ===============================
# GRPO Feedback Endpoints
# ===============================

class FeedbackCreateRequest(BaseModel):
    task_type: str = Field(..., description="scan_analysis, exploit_recommendation, or agent_decision")
    user_prompt: str
    model_response: str
    system_prompt: Optional[str] = None
    context: Optional[Dict] = None
    session_id: Optional[str] = None


class FeedbackRatingRequest(BaseModel):
    rating: int = Field(..., ge=1, le=5)
    rating_dimensions: Optional[Dict] = None
    reviewer_id: Optional[str] = None
    notes: Optional[str] = None


@app.post("/feedback")
async def submit_feedback(request: FeedbackCreateRequest):
    """Submit a new feedback entry (prompt/response pair for rating)."""
    try:
        sid = uuid.UUID(request.session_id) if request.session_id else None
        feedback_id = create_feedback(
            task_type=request.task_type,
            user_prompt=request.user_prompt,
            model_response=request.model_response,
            system_prompt=request.system_prompt,
            context=request.context,
            session_id=sid,
        )
        return {"feedback_id": str(feedback_id), "status": "created"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/feedback")
async def list_feedback_entries(
    task_type: Optional[str] = None,
    rated: Optional[bool] = None,
    session_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """List feedback entries with optional filtering."""
    try:
        sid = uuid.UUID(session_id) if session_id else None
        entries = list_feedback(
            task_type=task_type,
            rated=rated,
            session_id=sid,
            limit=limit,
            offset=offset,
        )
        return {
            "entries": [
                {
                    "id": str(e["id"]),
                    "task_type": e["task_type"],
                    "user_prompt": e["user_prompt"][:200],
                    "model_response": e["model_response"][:200],
                    "rating": e["rating"],
                    "rating_dimensions": e.get("rating_dimensions"),
                    "reviewer_id": e.get("reviewer_id"),
                    "session_id": str(e["session_id"]) if e.get("session_id") else None,
                    "used_in_training": e.get("used_in_training", False),
                    "created_at": e["created_at"].isoformat() if e.get("created_at") else None,
                }
                for e in entries
            ],
            "count": len(entries),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/feedback/stats")
async def feedback_stats():
    """Get aggregate feedback statistics by task type and rating distribution."""
    try:
        stats = get_feedback_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/feedback/export")
async def export_feedback_dataset(
    task_type: Optional[str] = None,
    min_rating: int = 1,
    dataset_version: Optional[str] = None,
):
    """Export rated feedback as JSONL training dataset."""
    try:
        task_types = [task_type] if task_type else None
        dataset = export_training_dataset(
            task_types=task_types,
            min_rating=min_rating,
            dataset_version=dataset_version,
        )
        return {
            "entries": dataset,
            "count": len(dataset),
            "dataset_version": dataset_version,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/feedback/{feedback_id}")
async def get_feedback_entry(feedback_id: str):
    """Get a single feedback entry by ID."""
    try:
        fid = uuid.UUID(feedback_id)
        entry = get_feedback(fid)
        if not entry:
            raise HTTPException(status_code=404, detail="Feedback entry not found")
        return {
            "id": str(entry["id"]),
            "task_type": entry["task_type"],
            "user_prompt": entry["user_prompt"],
            "model_response": entry["model_response"],
            "system_prompt": entry.get("system_prompt"),
            "context": entry.get("context"),
            "rating": entry["rating"],
            "rating_dimensions": entry.get("rating_dimensions"),
            "reviewer_id": entry.get("reviewer_id"),
            "review_notes": entry.get("review_notes"),
            "session_id": str(entry["session_id"]) if entry.get("session_id") else None,
            "agent_message_id": str(entry["agent_message_id"]) if entry.get("agent_message_id") else None,
            "dataset_version": entry.get("dataset_version"),
            "used_in_training": entry.get("used_in_training", False),
            "created_at": entry["created_at"].isoformat() if entry.get("created_at") else None,
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid feedback ID format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/feedback/{feedback_id}")
async def rate_feedback_entry(feedback_id: str, request: FeedbackRatingRequest):
    """Add or update a human rating on a feedback entry."""
    try:
        fid = uuid.UUID(feedback_id)
        success = update_feedback_rating(
            feedback_id=fid,
            rating=request.rating,
            rating_dimensions=request.rating_dimensions,
            reviewer_id=request.reviewer_id,
            notes=request.notes,
        )
        if not success:
            raise HTTPException(status_code=404, detail="Feedback entry not found")
        return {"feedback_id": feedback_id, "rating": request.rating, "status": "updated"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid feedback ID format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/feedback/capture/{session_id}")
async def capture_feedback_from_session(session_id: str):
    """
    Auto-capture agent outputs from a session as unrated feedback entries.
    Classifies messages by agent type into task categories.
    """
    try:
        sid = uuid.UUID(session_id)
        session = get_agent_session(sid)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        captured_ids = capture_session_outputs(sid)
        return {
            "session_id": session_id,
            "captured_count": len(captured_ids),
            "feedback_ids": [str(fid) for fid in captured_ids],
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===============================
# Prompt Configuration Endpoints
# ===============================

class PromptConfigCreate(BaseModel):
    name: str = Field(..., description="Unique name for this prompt configuration")
    description: Optional[str] = Field(None, description="Description of this config")
    prompts: Optional[Dict[str, str]] = Field(None, description="Agent role → system message mapping. If omitted, seeds from current defaults.")
    is_active: bool = Field(False, description="Set as the active prompt config")

class PromptConfigUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    prompts: Optional[Dict[str, str]] = None
    is_active: Optional[bool] = None

class PromptDuplicateRequest(BaseModel):
    new_name: str = Field(..., description="Name for the duplicated config")


@app.get("/config/prompts")
async def list_prompts():
    """List all saved prompt configurations."""
    from db_utils import list_prompt_configs
    configs = list_prompt_configs()
    return {
        "configs": [
            {
                "id": str(c["id"]),
                "name": c["name"],
                "description": c["description"],
                "is_active": c["is_active"],
                "created_at": c["created_at"].isoformat() if c["created_at"] else None,
                "updated_at": c["updated_at"].isoformat() if c["updated_at"] else None,
            }
            for c in configs
        ]
    }


@app.get("/config/prompts/active")
async def get_active_prompts():
    """Get the active prompt config, or the built-in defaults if none is active."""
    from db_utils import get_active_prompt_config
    from agent_config import SYSTEM_MESSAGES
    active = get_active_prompt_config()
    if active:
        return {
            "source": "database",
            "id": str(active["id"]),
            "name": active["name"],
            "description": active["description"],
            "prompts": active["prompts"],
            "created_at": active["created_at"].isoformat() if active["created_at"] else None,
        }
    return {
        "source": "defaults",
        "id": None,
        "name": "built-in-defaults",
        "description": "Hard-coded system messages from agent_config.py",
        "prompts": SYSTEM_MESSAGES,
    }


@app.get("/config/prompts/{config_id}")
async def get_prompt_config_endpoint(config_id: str):
    """Get a specific prompt configuration by ID."""
    from db_utils import get_prompt_config
    try:
        cid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config ID")
    config = get_prompt_config(cid)
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")
    return {
        "id": str(config["id"]),
        "name": config["name"],
        "description": config["description"],
        "prompts": config["prompts"],
        "is_active": config["is_active"],
        "created_at": config["created_at"].isoformat() if config["created_at"] else None,
        "updated_at": config["updated_at"].isoformat() if config["updated_at"] else None,
    }


@app.post("/config/prompts")
async def create_prompt_config_endpoint(req: PromptConfigCreate):
    """Create a new prompt configuration. Omit prompts to seed from current defaults."""
    from db_utils import create_prompt_config
    from agent_config import SYSTEM_MESSAGES
    prompts = req.prompts if req.prompts else dict(SYSTEM_MESSAGES)
    try:
        config_id = create_prompt_config(
            name=req.name,
            prompts=prompts,
            description=req.description,
            is_active=req.is_active,
        )
        return {"id": str(config_id), "name": req.name, "is_active": req.is_active}
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Name '{req.name}' already exists")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/config/prompts/{config_id}")
async def update_prompt_config_endpoint(config_id: str, req: PromptConfigUpdate):
    """Update an existing prompt configuration."""
    from db_utils import update_prompt_config
    try:
        cid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config ID")
    updated = update_prompt_config(
        config_id=cid,
        name=req.name,
        description=req.description,
        prompts=req.prompts,
        is_active=req.is_active,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Config not found")
    return {"ok": True, "id": config_id}


@app.post("/config/prompts/{config_id}/duplicate")
async def duplicate_prompt_config_endpoint(config_id: str, req: PromptDuplicateRequest):
    """Duplicate a prompt configuration with a new name."""
    from db_utils import duplicate_prompt_config
    try:
        cid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config ID")
    try:
        new_id = duplicate_prompt_config(cid, req.new_name)
        return {"id": str(new_id), "name": req.new_name, "duplicated_from": config_id}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail=f"Name '{req.new_name}' already exists")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/config/prompts/{config_id}")
async def delete_prompt_config_endpoint(config_id: str):
    """Delete a prompt configuration."""
    from db_utils import delete_prompt_config
    try:
        cid = uuid.UUID(config_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid config ID")
    deleted = delete_prompt_config(cid)
    if not deleted:
        raise HTTPException(status_code=404, detail="Config not found")
    return {"ok": True, "deleted": config_id}


@app.get("/model/performance-warning")
async def get_model_performance_warning():
    """
    Check if the current LLM model might cause performance issues for AI agent scans.
    Returns warnings and recommendations for model optimization.
    """
    try:
        # Get current model info
        ollama_url = os.environ.get("OLLAMA_URL", "http://ollama:11434")

        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                # Get loaded models
                response = await client.get(f"{ollama_url}/api/ps")
                loaded_models = response.json().get("models", [])

                # Get available models for recommendations
                tags_response = await client.get(f"{ollama_url}/api/tags")
                available_models = tags_response.json().get("models", [])

        except Exception as e:
            # If Ollama is not accessible, check environment
            current_model = os.environ.get("OLLAMA_MODEL", "unknown")
            loaded_models = [{"name": current_model, "size": 0}]
            available_models = []

        warnings = []
        recommendations = []
        performance_risk = "low"

        # Model performance rules
        slow_model_patterns = {
            # Pattern: (risk_level, reason, size_gb_estimate)
            "70b": ("high", "70B parameter models are too slow for real-time agent coordination", 40),
            "65b": ("high", "65B parameter models cause significant delays in agent responses", 35),
            "34b": ("high", "34B parameter models can cause session timeouts during scans", 20),
            "32b": ("high", "32B parameter models often cause stuck sessions in agent workflows", 18),
            "26b": ("medium", "26B parameter models may cause delays and memory pressure", 15),
            "20b": ("medium", "20B parameter models can slow down agent coordination", 12),
            "14b": ("medium", "14B parameter models may impact scan performance", 8),
        }

        fast_models = [
            {"name": "gemma4:8b", "reason": "Excellent balance of speed and capability for agent tasks"},
            {"name": "llama3.1:8b", "reason": "Fast inference with good reasoning abilities"},
            {"name": "qwen2.5:7b", "reason": "Very fast with strong tool-calling performance"},
            {"name": "gemma2:9b", "reason": "Good performance for complex agent coordination"},
            {"name": "mistral:7b", "reason": "Lightweight and fast for basic agent tasks"},
        ]

        current_model_name = "unknown"
        current_model_size = 0

        if loaded_models:
            current_model = loaded_models[0]
            current_model_name = current_model.get("name", "unknown")
            current_model_size = current_model.get("size", 0) / (1024**3)  # Convert to GB

            # Check against slow model patterns
            model_lower = current_model_name.lower()
            for pattern, (risk, reason, estimated_size) in slow_model_patterns.items():
                if pattern in model_lower:
                    performance_risk = risk
                    warnings.append({
                        "type": "model_size",
                        "severity": risk,
                        "message": f"Current model '{current_model_name}' may cause performance issues",
                        "details": reason,
                        "estimated_response_time": "10-30 seconds" if risk == "high" else "5-15 seconds"
                    })
                    break

            # Memory usage warning
            if current_model_size > 15:  # > 15GB
                warnings.append({
                    "type": "memory_usage",
                    "severity": "medium",
                    "message": f"Model using ~{current_model_size:.1f}GB memory may impact system stability",
                    "details": "High memory usage can cause GPU memory pressure and slower inference"
                })

        # Add recommendations if warnings exist
        if warnings:
            recommendations.extend([
                {
                    "type": "model_switch",
                    "action": f"Switch to a faster model like {fast_models[0]['name']}",
                    "benefit": "3-6x faster responses, more stable agent sessions",
                    "models": fast_models[:3]
                },
                {
                    "type": "timeout_adjustment",
                    "action": "Dynamic timeouts are enabled to help with slower models",
                    "benefit": "Automatic timeout scaling based on scan scope"
                }
            ])

        # Check if fast models are available
        available_fast = []
        for model in available_models:
            model_name = model.get("name", "")
            if any(fast["name"] in model_name for fast in fast_models):
                available_fast.append(model_name)

        return {
            "performance_risk": performance_risk,
            "current_model": current_model_name,
            "model_size_gb": round(current_model_size, 1) if current_model_size > 0 else None,
            "warnings": warnings,
            "recommendations": recommendations,
            "available_fast_models": available_fast,
            "optimal_models_for_agents": fast_models[:3]
        }

    except Exception as e:
        session_logger.error(f"Error checking model performance: {e}")
        return {
            "performance_risk": "unknown",
            "current_model": "unknown",
            "warnings": [{
                "type": "check_failed",
                "severity": "low",
                "message": "Could not determine model performance characteristics",
                "details": str(e)
            }],
            "recommendations": [],
            "available_fast_models": [],
            "optimal_models_for_agents": []
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8015, ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))
