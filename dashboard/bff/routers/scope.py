from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


@router.get("/api/scope/names")
async def list_scope_names():
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/names",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope")
async def get_scope(
    name: str = Query("default"),
    limit: int = Query(500, le=5000),
):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope",
            params={"name": name, "limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope/export.csv")
async def export_scope_csv(
    name: Optional[str] = Query(None),
    all_engagements: bool = Query(False),
    include_placeholders: bool = Query(False),
):
    """Stream the scope-targets CSV through from rag-api.

    NOT safe_json: the upstream body is text/csv, and the browser needs the
    Content-Disposition filename to survive so "Save as" offers the right name.
    """
    s = get_settings()
    params = {"all_engagements": str(all_engagements).lower(),
              "include_placeholders": str(include_placeholders).lower()}
    if name:
        params["name"] = name
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/export.csv",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
    if resp.status_code >= 400:
        # An HTTP status is not an exception (CLAUDE.md): httpx does not raise
        # on 4xx/5xx, so without this the operator downloads a file containing
        # the error body and reads it as an empty scope.
        raise HTTPException(resp.status_code, resp.text[:500])
    return Response(
        content=resp.content,
        media_type="text/csv",
        headers={"Content-Disposition":
                 resp.headers.get("content-disposition", 'attachment; filename="scope-targets.csv"')},
    )


class AddToScopeBody(BaseModel):
    name: str = "default"
    targets: list[dict]


@router.post("/api/scope/add")
async def add_to_scope(body: AddToScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/add",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/{name}/purge-data")
async def purge_scope_data(name: str, body: dict = None, dry_run: bool = Query(False)):
    """Delete all findings, follow-ups, and recommendations for a named scope's
    targets (dry_run previews counts). Keeps assets/ports/scope so a rerun is
    authorised and regenerates fresh data."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/{name}/purge-data",
            params={"dry_run": str(dry_run).lower()},
            json=body or {},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class RemoveFromScopeBody(BaseModel):
    name: str = "default"
    targets: list[str]


@router.delete("/api/scope/targets")
async def remove_from_scope(body: RemoveFromScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/scope/targets",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/move")
async def move_scope_targets(request: Request):
    """Move targets between scopes.

    300s, not 15s. The move does per-target work — rule distillation and an
    embedder call each — so a 77-target move ran well past 15 seconds. httpx
    raised ReadTimeout, this proxy 500'd, and the operator saw
    "API 500: Internal Server Error" — while rag-api carried on and COMPLETED
    the move. The UI reported failure for a mutation that had succeeded, which
    invites a retry on data that already changed.

    The status is checked too, so a genuine upstream error is reported as that
    error rather than as whatever safe_json makes of the body.
    """
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(timeout=300) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/move",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])
        return safe_json(resp)


@router.post("/api/scope/cleanup-unknown")
async def cleanup_unknown_scope():
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/cleanup-unknown",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope/auto-assign-unknown")
async def auto_assign_unknown():
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/auto-assign-unknown",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class ExcludeBody(BaseModel):
    targets: list[str]
    source: str = "manual"


@router.post("/api/scope/exclude")
async def exclude_from_scope(body: ExcludeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope/exclude",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/scope/exclude")
async def remove_exclusion(body: RemoveFromScopeBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.request(
            "DELETE",
            f"{s.rag_api_url}/scope/exclude",
            json={"targets": body.targets},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope/excluded")
async def list_excluded():
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope/excluded",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ─── OSINT scope-pivot (typosquats + cert / ASN pivots) ─────────────────────
# The rag-api endpoints land at /scope-pivot/*; these are thin BFF proxies so
# the dashboard's apiFetch -> /api/scope-pivot/* reaches them.

@router.post("/api/scope-pivot/typosquat/{engagement_id}")
async def run_typosquat_pivot(
    engagement_id: str,
    check_resolution: bool = Query(False),
    auto_block_at: float = Query(0.85),
):
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/typosquat/{engagement_id}",
            params={
                "check_resolution": str(check_resolution).lower(),
                "auto_block_at": auto_block_at,
            },
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope-pivot/cert/{engagement_id}")
async def run_cert_pivot(
    engagement_id: str,
    limit: int = Query(500, le=1000),
):
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/cert/{engagement_id}",
            params={"limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/scope-pivot/asn/{engagement_id}")
async def run_asn_pivot(
    engagement_id: str,
    limit: int = Query(500, le=1000),
):
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/asn/{engagement_id}",
            params={"limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/scope-pivot/suggestions")
async def list_pivot_suggestions(
    status: Optional[str] = Query(None),
    method: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
):
    s = get_settings()
    params = {"limit": limit}
    if status: params["status"] = status
    if method: params["method"] = method
    async with httpx.AsyncClient(timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/scope-pivot/suggestions",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class ReviewPivotBody(BaseModel):
    action: str  # "accept" | "reject"


@router.post("/api/scope-pivot/suggestions/{suggestion_id}/review")
async def review_pivot_suggestion(suggestion_id: str, body: ReviewPivotBody):
    s = get_settings()
    async with httpx.AsyncClient(timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/suggestions/{suggestion_id}/review",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class BulkReviewPivotBody(BaseModel):
    ids: list[str]
    action: str  # "accept" | "reject"


@router.post("/api/scope-pivot/suggestions/review-bulk")
async def review_pivot_suggestions_bulk(body: BulkReviewPivotBody):
    """Bulk operator review — up to 500 ids per call, one rag-api round-trip
    + one DB transaction, so the UI can confirm/reject a page of
    suggestions without 500 serial requests."""
    s = get_settings()
    async with httpx.AsyncClient(timeout=120) as c:
        resp = await c.post(
            f"{s.rag_api_url}/scope-pivot/suggestions/review-bulk",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class AutoClassifyBody(BaseModel):
    """Mirrors rag-api's AutoClassifyBody. `generate_rules` defaults to FALSE
    here: seeding rules is a side effect the operator should ask for, not
    something a classify button does quietly."""
    generate_rules: bool = False
    unknown_scope: str = "unknown_scope"
    limit: Optional[int] = None


@router.post("/api/engagements/{engagement_id}/scope/auto-classify")
async def auto_classify_engagement_scope(engagement_id: str, body: AutoClassifyBody | None = None):
    """Classify every DISCOVERED host for this engagement into a scope.

    Only touches hosts that are not already in `scope_targets` for the
    engagement — it assigns newly discovered hosts and never re-files existing
    ones, which is worth knowing before expecting it to reorganise a scope.

    This route existed on rag-api with no proxy, so the dashboard got a 404 and
    the whole feature was CLI-only. Long timeout: it walks every discovered host
    (145 candidates took a few seconds, but a first run on a large engagement
    walks thousands).
    """
    s = get_settings()
    async with httpx.AsyncClient(timeout=600) as c:
        resp = await c.post(
            f"{s.rag_api_url}/engagements/{engagement_id}/scope/auto-classify",
            json=(body or AutoClassifyBody()).model_dump(),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])
        return safe_json(resp)
