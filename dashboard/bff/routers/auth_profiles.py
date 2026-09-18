"""Auth Profiles — BFF proxy to the web Auth Profile store (playwright-scanner
/web-auth) and to rag-api's auto-populate + Burp-bundle. One portable, tool-
agnostic web-auth model that drives the platform's scanners and feeds Burp."""

import httpx
from fastapi import APIRouter, HTTPException, Request
from config import get_settings
from engagement import engagement_headers

router = APIRouter()


def _ps() -> str:
    return get_settings().playwright_scanner_url.rstrip("/")


def _rag() -> str:
    return get_settings().rag_api_url.rstrip("/")


def _hdrs() -> dict:
    s = get_settings()
    return {"x-api-key": s.api_key, **engagement_headers()}


@router.get("/api/auth-profiles")
async def list_auth_profiles():
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as c:
            r = await c.get(f"{_ps()}/web-auth", headers=_hdrs())
            return r.json() if r.status_code == 200 else {"configs": [], "error": r.text[:200]}
    except Exception as e:
        raise HTTPException(502, f"auth-profiles list failed: {e}")


@router.post("/api/auth-profiles")
async def upsert_auth_profile(request: Request):
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as c:
            r = await c.post(f"{_ps()}/web-auth", json=body, headers=_hdrs())
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text[:300])
            return r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"auth-profile save failed: {e}")


@router.delete("/api/auth-profiles/{host}")
async def delete_auth_profile(host: str, engagement_id: str = None):
    params = {"engagement_id": engagement_id} if engagement_id else None
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as c:
            r = await c.delete(f"{_ps()}/web-auth/{host}", params=params, headers=_hdrs())
            return r.json() if r.status_code < 400 else {"ok": False, "error": r.text[:200]}
    except Exception as e:
        raise HTTPException(502, f"auth-profile delete failed: {e}")


@router.post("/api/auth-profiles/auto-populate")
async def auto_populate(request: Request):
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=40, verify=False) as c:
            r = await c.post(f"{_rag()}/auth-profiles/auto-populate", json=body, headers=_hdrs())
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text[:300])
            return r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"auto-populate failed: {e}")


@router.post("/api/auth-profiles/import-session")
async def import_session(request: Request):
    """Manual import of an interactively-obtained session (SSO/OAuth/MFA done in
    the operator's own browser) → session-only Auth Profile."""
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as c:
            r = await c.post(f"{_ps()}/auth/import-session", json=body, headers=_hdrs())
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text[:300])
            return r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"import-session failed: {e}")


@router.post("/api/auth-profiles/interactive-login")
async def interactive_login(request: Request):
    """Assisted browser login (SSO/OAuth/OIDC/SAML, +TOTP) that captures the
    session into an Auth Profile. Long timeout — drives a real browser."""
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=120, verify=False) as c:
            r = await c.post(f"{_ps()}/auth/interactive-login", json=body, headers=_hdrs())
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text[:300])
            return r.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"interactive-login failed: {e}")


@router.post("/api/auth-profiles/interactive-login/{sid}/otp")
async def interactive_login_otp(sid: str, request: Request):
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=60, verify=False) as c:
            r = await c.post(f"{_ps()}/auth/interactive-login/{sid}/otp", json=body, headers=_hdrs())
            return r.json() if r.status_code < 400 else {"ok": False, "error": r.text[:200]}
    except Exception as e:
        raise HTTPException(502, f"interactive-login otp failed: {e}")


@router.post("/api/auth-profiles/oauth-capture")
async def oauth_capture(request: Request):
    """OAuth2 token capture (client_credentials / authorization_code / intercept)
    → persist into an Auth Profile."""
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=120, verify=False) as c:
            r = await c.post(f"{_ps()}/auth/capture", json=body, headers=_hdrs())
            return r.json() if r.status_code < 400 else {"ok": False, "error": r.text[:300]}
    except Exception as e:
        raise HTTPException(502, f"oauth-capture failed: {e}")


@router.post("/api/auth-profiles/device-poll")
async def device_poll(request: Request):
    """Poll the token endpoint once for an in-progress device-code grant."""
    body = await request.json()
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as c:
            r = await c.post(f"{_ps()}/auth/device-poll", json=body, headers=_hdrs())
            return r.json() if r.status_code < 400 else {"ok": False, "error": r.text[:200]}
    except Exception as e:
        raise HTTPException(502, f"device-poll failed: {e}")


@router.get("/api/auth-profiles/burp-bundle")
async def burp_bundle(host: str, engagement_id: str = None):
    params = {"host": host}
    if engagement_id:
        params["engagement_id"] = engagement_id
    try:
        async with httpx.AsyncClient(timeout=20, verify=False) as c:
            r = await c.get(f"{_rag()}/auth-profiles/burp-bundle", params=params, headers=_hdrs())
            return r.json() if r.status_code < 400 else {"ok": False, "error": r.text[:200]}
    except Exception as e:
        raise HTTPException(502, f"burp-bundle failed: {e}")
