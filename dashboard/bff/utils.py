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
        raise HTTPException(resp.status_code, resp.text[:500])
    try:
        return resp.json()
    except Exception:
        raise HTTPException(502, f"Invalid JSON from upstream: {resp.text[:200]}")
