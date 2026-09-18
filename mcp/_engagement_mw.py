"""Per-request engagement propagation for the streamable MCP servers.

The mcpo gateway calls these FastMCP servers over HTTP. When the caller supplies
the engagement per request — as an `X-Engagement-Id` header OR an
`?engagement_id=` query param — this middleware captures it into a contextvar for
the duration of that request, so the server's rag-api calls carry it and that ONE
tool call is scoped to that engagement.

Resolution order (most specific first):
  1. per-request contextvar  (this request's header/query)
  2. ENGAGEMENT_ID / MCP_ENGAGEMENT_ID env  (a per-server pin)
  3. unset -> platform-wide (unchanged behaviour)
"""
import os
import contextvars

_REQ_ENGAGEMENT = contextvars.ContextVar("mcp_req_engagement", default=None)
_ENV_ENGAGEMENT = os.environ.get("ENGAGEMENT_ID") or os.environ.get("MCP_ENGAGEMENT_ID")


def current_engagement():
    """The engagement for the current request: per-request value, else env pin."""
    return _REQ_ENGAGEMENT.get() or _ENV_ENGAGEMENT


def set_request_engagement(eid):
    """Set the per-request engagement for THIS tool call (from a tool's
    `engagement_id` argument). mcpo forwards only declared tool parameters — not
    headers or query — so a tool that accepts `engagement_id` and calls this is
    the reliable way for a caller to scope a single tool call through the gateway.
    A blank/None value leaves resolution to the header (direct clients) or env."""
    v = (str(eid).strip() if eid else "")
    if v:
        _REQ_ENGAGEMENT.set(v)


def api_headers(api_key, extra=None):
    """rag-api headers carrying the current engagement (if any)."""
    h = {"x-api-key": api_key}
    eid = current_engagement()
    if eid:
        h["X-Engagement-Id"] = eid
    if extra:
        h.update(extra)
    return h


class EngagementMiddleware:
    """Pure-ASGI middleware: bind X-Engagement-Id (header or ?engagement_id query)
    to the contextvar for each HTTP request, resetting it afterwards."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        eid = None
        for k, v in scope.get("headers") or []:
            if k == b"x-engagement-id":
                eid = v.decode("latin-1").strip() or None
                break
        if not eid:
            qs = scope.get("query_string") or b""
            if b"engagement_id=" in qs:
                from urllib.parse import parse_qs
                vals = parse_qs(qs.decode("latin-1")).get("engagement_id")
                if vals:
                    eid = (vals[0] or "").strip() or None
        token = _REQ_ENGAGEMENT.set(eid)
        try:
            await self.app(scope, receive, send)
        finally:
            _REQ_ENGAGEMENT.reset(token)


def run_streamable(mcp):
    """Run a FastMCP streamable server with the engagement middleware installed."""
    import uvicorn
    app = mcp.streamable_http_app()
    app.add_middleware(EngagementMiddleware)
    uvicorn.run(app, host=mcp.settings.host, port=mcp.settings.port, log_level="info")
