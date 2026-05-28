"""
BFF-side engagement context capture + outgoing-header helper.

Mirrors the rag-api side (``app/rag-api/api.py::current_engagement_id``):
incoming requests carry ``X-Engagement-Id`` set by the frontend
(`dashboard/frontend/src/api/client.ts`), middleware captures it into a
contextvar, and helpers expose it so any BFF → rag-api call can forward
the header through.

The forward step is critical: without it, the rag-api middleware sees no
header on requests proxied through the BFF, ``_resolve_engagement_id()``
returns None, and ``INSERT INTO jobs`` rows land with ``engagement_id =
NULL`` -- effectively bypassing the Option B isolation.

Usage on a BFF route::

    from engagement import engagement_headers

    async with httpx.AsyncClient(...) as c:
        r = await c.post(
            f"{settings.rag_api_url}/jobs/...",
            json=payload,
            headers={"x-api-key": settings.api_key, **engagement_headers()},
        )

The helper returns an empty dict when no engagement is active, so callers
unconditionally spread it without branching.
"""

from __future__ import annotations

import contextvars
from typing import Dict


# Request-scoped contextvar set by `engagement_middleware` from the
# incoming ``X-Engagement-Id`` header.  None when no engagement is active.
current_engagement_id: contextvars.ContextVar = contextvars.ContextVar(
    "bff_current_engagement_id", default=None,
)


async def engagement_middleware(request, call_next):
    """FastAPI HTTP middleware: bind X-Engagement-Id from the incoming
    request to the contextvar for this request's lifetime, then reset on
    response so it doesn't leak between requests."""
    eid = (
        request.headers.get("x-engagement-id")
        or request.headers.get("X-Engagement-Id")
    )
    token = current_engagement_id.set(eid or None)
    try:
        return await call_next(request)
    finally:
        current_engagement_id.reset(token)


def engagement_headers() -> Dict[str, str]:
    """Return ``{"X-Engagement-Id": <eid>}`` when an engagement is active,
    or an empty dict.  Spread into outgoing httpx ``headers={...}`` so the
    rag-api middleware can capture it on the other side.

    Returns an empty dict (instead of raising) when called outside any
    request context (e.g. background poll loop) -- callers don't need to
    branch."""
    try:
        eid = current_engagement_id.get()
    except LookupError:
        return {}
    return {"X-Engagement-Id": eid} if eid else {}
