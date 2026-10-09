"""Shared BFF utilities."""
import httpx
from fastapi import HTTPException


def safe_json(resp: httpx.Response):
    """Parse JSON from httpx response, raising HTTPException on error.

    Use this instead of bare `resp.json()` in all BFF proxy endpoints
    so upstream errors return a readable HTTP error to the frontend
    instead of crashing with 'JSON.parse: unexpected character'.
    """
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, _upstream_detail(resp))
    try:
        return resp.json()
    except Exception:
        raise HTTPException(502, f"Invalid JSON from upstream: {resp.text[:200]}")


def _upstream_detail(resp: httpx.Response) -> str:
    """Return the useful error reason from an upstream FastAPI service.

    Upstream handlers raise `HTTPException(status, "DigitalOcean create droplet
    rejected: unprocessable_entity — Size is not available in this region.")`
    which FastAPI serializes as JSON `{"detail": "..."}`. Passing `resp.text`
    straight through nests the JSON inside the proxy's own `detail` string, and
    the frontend has to double-parse to reach the message. Unwrap once here.
    See 2026-10-06 CHANGES_MADE.
    """
    try:
        body = resp.json()
        if isinstance(body, dict):
            d = body.get("detail")
            if isinstance(d, str):
                return d
            if d is not None:
                import json as _json
                return _json.dumps(d)
    except Exception:
        pass
    return (resp.text or f"HTTP {resp.status_code}")[:800]


def raise_upstream(resp: httpx.Response) -> None:
    """Convenience: re-raise an upstream 4xx/5xx with the unwrapped detail."""
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, _upstream_detail(resp))
