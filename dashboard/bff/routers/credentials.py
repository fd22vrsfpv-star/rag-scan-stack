from typing import Optional
import httpx
from fastapi import APIRouter, Query
from pydantic import BaseModel
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


class CredentialBody(BaseModel):
    username: str
    domain: Optional[str] = None
    credential_type: str
    credential_value: Optional[str] = None
    cracked_value: Optional[str] = None
    source: str
    source_entity_id: Optional[str] = None
    status: str = "active"
    access_level: Optional[str] = None
    grants_access_to: Optional[list[str]] = None
    notes: Optional[str] = None
    engagement_id: Optional[str] = None
    expires_at: Optional[str] = None
    cloud_metadata: Optional[dict] = None
    permissions_summary: Optional[str] = None


@router.post("/api/credential-vault")
async def create_credential(body: CredentialBody):
    s = get_settings()
    from fastapi import HTTPException
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/credential-vault",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/credential-vault")
async def list_credentials(
    engagement_id: Optional[str] = Query(None),
    credential_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
):
    s = get_settings()
    params = {}
    if engagement_id:
        params["engagement_id"] = engagement_id
    if credential_type:
        params["credential_type"] = credential_type
    if status:
        params["status"] = status
    if domain:
        params["domain"] = domain
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/credential-vault",
            params=params,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class CredentialUpdateBody(BaseModel):
    status: Optional[str] = None
    cracked_value: Optional[str] = None
    access_level: Optional[str] = None
    notes: Optional[str] = None
    grants_access_to: Optional[list[str]] = None
    expires_at: Optional[str] = None
    cloud_metadata: Optional[dict] = None
    permissions_summary: Optional[str] = None


@router.patch("/api/credential-vault/{cid}")
async def update_credential(cid: str, body: CredentialUpdateBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/credential-vault/{cid}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/credential-vault/{cid}")
async def delete_credential_vault(cid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/credential-vault/{cid}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/credential-vault/expiring")
async def credentials_expiring(minutes: int = Query(30)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/credential-vault/expiring",
            params={"minutes": minutes},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


# ── Vault import agent (replaces "Navigate to Credentials" dead-end) ───


class VaultImportBody(BaseModel):
    source: str = "microburst"
    finding_types: Optional[list[str]] = None
    engagement_id: Optional[str] = None
    dry_run: bool = True
    limit: int = 200
    model: Optional[str] = None


@router.post("/api/vault/import-from-recon")
async def vault_import_from_recon(body: VaultImportBody):
    """Two-phase: dry_run=true returns the AI's proposals for operator review;
    dry_run=false commits them. LLM-driven extraction of heterogeneous
    secret column conventions (MicroBurst KeyVault / Storage / AppService /
    Get-AzPasswords) into normalized credential_vault rows."""
    from fastapi import HTTPException
    s = get_settings()
    # Generous timeout: per-row LLM call + commit phase can take a while
    async with httpx.AsyncClient(verify=False, timeout=600) as c:
        resp = await c.post(
            f"{s.rag_api_url}/vault/import-from-recon",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.patch("/api/credential-vault/{cid}/refresh-expiry")
async def refresh_credential_expiry(cid: str, body: dict):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/credential-vault/{cid}/refresh-expiry",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/credential-vault/cloud-summary")
async def credential_cloud_summary():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/credential-vault/cloud-summary",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/credential-access-map/{credential_id}")
async def list_access_map(credential_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/credential-access-map/{credential_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


class AccessMapBody(BaseModel):
    credential_id: str
    resource_type: str
    resource_id: str
    access_level: Optional[str] = None
    verified: bool = False
    source: Optional[str] = None
    metadata: Optional[dict] = None


@router.post("/api/credential-access-map")
async def create_access_map(body: AccessMapBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/credential-access-map",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/credential-access-map/{map_id}")
async def delete_access_map(map_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/credential-access-map/{map_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)
