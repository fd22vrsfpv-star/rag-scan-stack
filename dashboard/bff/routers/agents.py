"""BFF proxy endpoints for the AI Agents page and gap analysis."""
import httpx
from fastapi import APIRouter, Query, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from config import get_settings
from engagement import engagement_headers
from timeouts import TIMEOUT_NORMAL, TIMEOUT_LONG
from utils import safe_json

router = APIRouter()


# ── Agents Status ──────────────────────────────────────────────────────

@router.get("/api/agents/status")
async def agents_status():
    """Aggregate status of all AI agents."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agents/status",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# ── Agent Feedback channel (agent_flags) ───────────────────────────────

@router.get("/api/agent-flags")
async def list_agent_flags(status: Optional[str] = None, engagement_id: Optional[str] = None):
    s = get_settings()
    params = {k: v for k, v in (("status", status), ("engagement_id", engagement_id)) if v}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent-flags", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# The actions /api/agent-flags/{flag_id}/{action} forwards. A module-level
# constant rather than an inline tuple so tests/test_proxy_contracts.py can
# enumerate them and prove each one resolves to a declared rag-api route
# (DYNAMIC_SEGMENT_SOURCES). Before this the guard could not read the second
# path segment and reported the call as an upstream that no service declares.
AGENT_FLAG_ACTIONS = ("approve", "dismiss")


@router.post("/api/agent-flags/{flag_id}/{action}")
async def act_agent_flag(flag_id: str, action: str):
    if action not in AGENT_FLAG_ACTIONS:
        raise HTTPException(400, f"action must be one of {AGENT_FLAG_ACTIONS}")
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent-flags/{flag_id}/{action}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Self-adapting extractors (extractor_learned) ────────────────────────

@router.get("/api/extractors/learned")
async def list_extractors_learned(status: Optional[str] = None, tool: Optional[str] = None):
    s = get_settings()
    params = {k: v for k, v in (("status", status), ("tool", tool)) if v}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/extractors/learned", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/extractors/learned/{rule_id}/{action}")
async def review_extractor_learned(rule_id: str, action: str):
    if action not in ("approve", "reject"):
        raise HTTPException(400, "action must be approve or reject")
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/extractors/learned/{rule_id}/{action}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/extractors/export")
async def export_extractors(tool: Optional[str] = None):
    s = get_settings()
    params = {"tool": tool} if tool else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/extractors/export", params=params,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/agent-activity")
async def agent_activity(limit: int = 120, event_type: Optional[str] = None,
                         status: Optional[str] = None):
    """Cross-agent action timeline: proxy the webhook event-log (every agent
    action emits an event via /webhooks/emit), newest first."""
    s = get_settings()
    params: dict = {"limit": max(1, min(limit, 200))}
    if event_type:
        params["event_type"] = event_type
    if status:
        params["status"] = status
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/webhooks/events", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/extractors/analyze")
async def analyze_extractor(body: dict):
    """Preview what a profile extracts from an artifact, and optionally send it to
    the LLM to distil new rules (learn=true, may take a while → long timeout)."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/extractors/analyze", json=body,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Parser coverage ─────────────────────────────────────────────────────
#
# "No parser exists" is a different state from "the parser found nothing", and
# only the first is actionable. These make the gap visible and give it a fix.

@router.get("/api/parsers/missing")
async def parsers_missing(limit: int = 20, min_bytes: int = 200):
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/parsers/missing",
                           params={"limit": limit, "min_bytes": min_bytes},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/parsers/draft")
async def draft_parser(body: dict):
    """Preview by default; `learn: true` authors rules from a stored sample and
    may call the LLM, so it gets the long timeout."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/parsers/draft", json=body,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Methodology playbooks ───────────────────────────────────────────────
#
# The playbooks were RAG context only. These proxies make the extracted steps
# reachable from the dashboard. They answer questions and dispatch nothing.

@router.get("/api/playbooks")
async def list_playbooks():
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/playbooks",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/playbooks/checklist")
async def playbook_checklist(service: str = "", playbook: Optional[str] = None,
                             access: str = "none", target: Optional[str] = None,
                             port: Optional[int] = None, username: Optional[str] = None,
                             include_mutating: bool = False):
    """What the methodology says to check on this host, target filled in."""
    s = get_settings()
    params: dict = {"service": service, "access": access,
                    "include_mutating": str(bool(include_mutating)).lower()}
    for k, v in (("playbook", playbook), ("target", target),
                 ("port", port), ("username", username)):
        if v is not None:
            params[k] = v
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/playbooks/checklist", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/playbooks/coverage")
async def playbook_coverage(service: str, access: str = "shell",
                            done: Optional[str] = None):
    s = get_settings()
    params: dict = {"service": service, "access": access}
    if done:
        params["done"] = done
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/playbooks/coverage", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/playbooks/{name}")
async def get_playbook(name: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/playbooks/{name}",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Post-execution review (post_review_agent) ───────────────────────────
#
# The agent has existed for a while and had NO proxy, so none of it was reachable
# from the dashboard — /api/agent/post-review was a 404 and the only way to run a
# review was curl against rag-api with the API key. It classifies executed work
# and finds results that were captured but never interpreted; on this stack that
# was four SMB findings sitting in raw output, one of them high severity.
#
# It proposes and never dispatches: re-runs land as pending recommendations that
# a human still has to run, and every proposed target passes the scope gate
# first with refusals reported rather than dropped.

@router.post("/api/agent/post-review")
async def run_post_review(queue_reruns: bool = False, since_days: Optional[int] = None,
                          target: Optional[str] = None):
    """Classify every stored execution and report what was missed.

    Synchronous upstream — the report IS the answer — so it gets the long
    timeout rather than a fast fail that would abandon work already done."""
    s = get_settings()
    params: dict = {"queue_reruns": str(bool(queue_reruns)).lower()}
    if since_days is not None:
        params["since_days"] = since_days
    if target:
        params["target"] = target
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/post-review", params=params,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/agent/post-review/ingest-facts")
async def ingest_post_review_facts(dry_run: bool = True, target: Optional[str] = None,
                                   limit: int = 4000):
    """Store facts the review found in raw output as real findings.

    Defaults to a dry run, matching upstream: this writes findings that appear
    in reports and exports, so the default must not be the destructive one."""
    s = get_settings()
    params: dict = {"dry_run": str(bool(dry_run)).lower(), "limit": limit}
    if target:
        params["target"] = target
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/post-review/ingest-facts",
                            params=params,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent/post-review/executions/{execution_id}")
async def get_reviewed_execution(execution_id: str):
    """One execution in full, for manual review: the complete output, the return
    code, the flags it was actually called with, what the analysis extracted, and
    what the tool-selection learner made of it.

    The three verdicts answer different questions and a reviewer needs all of
    them: `classification` says what to DO about the run, `analysis` says what
    was IN its output, `learning` says what the platform learned from it."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.get(
            f"{s.rag_api_url}/agent/post-review/executions/{execution_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent/post-review/invocations")
async def post_review_invocations(tool: Optional[str] = None, limit: int = 200):
    """Return code x option signature per tool — which invocation form works.
    "nmap failed" was never a usable statement; this is what makes it one."""
    s = get_settings()
    params: dict = {"limit": max(1, min(limit, 2000))}
    if tool:
        params["tool"] = tool
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/post-review/invocations",
                           params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/agent/post-review/reports")
async def list_post_review_reports(limit: int = 20):
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/post-review/reports",
                           params={"limit": limit},
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/agent/post-review/reports/{report_id}")
async def get_post_review_report(report_id: str):
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/post-review/reports/{report_id}",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/agent/post-review/analysis-coverage")
async def post_review_analysis_coverage():
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/post-review/analysis-coverage",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# ── Learned tool selection (tool_selection_learned) ─────────────────────
#
# Review surface for etl/tool_learning.py. These rules decide which authorised
# tool is tried FIRST when another one fails; they never decide whether
# something may run. Approving one grants no permission.

@router.get("/api/tool-selection/learned")
async def list_tool_selection_learned(
        phase: Optional[str] = None, service: Optional[str] = None,
        status: Optional[str] = None, failed_tool: Optional[str] = None,
        limit: int = 200):
    s = get_settings()
    params = {k: v for k, v in (("phase", phase), ("service", service),
                                ("status", status), ("failed_tool", failed_tool))
              if v is not None}
    params["limit"] = max(1, min(limit, 1000))
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/tool-selection/learned", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/tool-selection/attempts")
async def list_tool_selection_attempts(
        phase: Optional[str] = None, service: Optional[str] = None,
        tool: Optional[str] = None, target: Optional[str] = None,
        signature: Optional[str] = None, limit: int = 100):
    """The raw observations behind a rule — a conclusion nobody can check is not
    reviewable."""
    s = get_settings()
    params = {k: v for k, v in (("phase", phase), ("service", service),
                                ("tool", tool), ("target", target),
                                ("signature", signature)) if v is not None}
    params["limit"] = max(1, min(limit, 1000))
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/tool-selection/attempts", params=params,
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/tool-selection/learned/{rule_id}/{action}")
async def review_tool_selection_learned(rule_id: str, action: str):
    if action not in ("approve", "reject", "reset"):
        raise HTTPException(400, "action must be approve, reject or reset")
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(
            f"{s.rag_api_url}/tool-selection/learned/{rule_id}/{action}",
            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/tool-selection/backfill")
async def backfill_tool_selection(body: dict):
    """Re-derive rules from tool_executions. Reads history only — dispatches
    nothing — but it can rewrite every rule for a phase, so it gets the long
    timeout rather than a fast fail."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/tool-selection/backfill", json=body,
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── Gap Analysis ───────────────────────────────────────────────────────

@router.post("/api/gap-analysis/{eid}")
async def trigger_gap_analysis(eid: str):
    """Trigger recon gap analysis for an engagement."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}",
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/gap-analysis/{eid}")
async def get_gap_report(eid: str, all: bool = Query(False)):
    """Get latest (or all) gap analysis report(s)."""
    s = get_settings()
    params = {"all": str(all).lower()} if all else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/gap-analysis/{eid}",
                           params=params, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/gap-analysis/{eid}/auto-fill")
async def auto_fill_gaps(eid: str, report_id: Optional[str] = Query(None)):
    """Dispatch passive scans to fill gaps."""
    s = get_settings()
    params = {}
    if report_id:
        params["report_id"] = report_id
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}/auto-fill",
                            params=params, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.get("/api/gap-analysis/{eid}/schedule")
async def get_gap_schedule(eid: str):
    """Get gap analysis auto-schedule config."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.get(f"{s.rag_api_url}/agent/gap-analysis/{eid}/schedule",
                           headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


@router.post("/api/gap-analysis/{eid}/schedule")
async def set_gap_schedule(eid: str, request: Request):
    """Set gap analysis auto-schedule config."""
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(timeout=TIMEOUT_NORMAL) as c:
        resp = await c.post(f"{s.rag_api_url}/agent/gap-analysis/{eid}/schedule",
                            json=body, headers={"x-api-key": s.api_key, **engagement_headers()})
        return safe_json(resp)


# ── Subdomain Takeover Hunter ──────────────────────────────────────────

class TakeoverRunBody(BaseModel):
    engagement_ids: Optional[list[str]] = None
    dry_run: bool = False
    limit: int = 5000
    concurrency: int = 50
    force: bool = False


@router.post("/api/agents/takeover-hunter/run")
async def takeover_hunter_run(body: TakeoverRunBody):
    """Run the subdomain takeover hunter. Active engagements only by default;
    routes through the configured proxy. Supports dry_run for preview, force
    to bypass the agent-side 10-min debounce."""
    s = get_settings()
    # Long timeout: 5,000 candidates × 50 concurrency × 6s timeout could take
    # several minutes worst-case. Use TIMEOUT_LONG so the BFF doesn't 504.
    async with httpx.AsyncClient(timeout=TIMEOUT_LONG) as c:
        resp = await c.post(f"{s.rag_api_url}/agents/takeover-hunter/run",
                            json=body.model_dump(exclude_none=True),
                            headers={"x-api-key": s.api_key, **engagement_headers()})
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()
