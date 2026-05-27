from typing import Optional
import httpx
from fastapi import APIRouter, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from config import get_settings
import io
from utils import safe_json

router = APIRouter()


@router.post("/api/evidence/upload")
async def upload_evidence(
    file: UploadFile = File(...),
    title: str = Query(...),
    evidence_type: str = Query("file"),
    engagement_id: Optional[str] = Query(None),
    description: Optional[str] = Query(None),
    uploaded_by: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
):
    s = get_settings()
    content = await file.read()
    params = {"title": title, "evidence_type": evidence_type}
    if engagement_id:
        params["engagement_id"] = engagement_id
    if description:
        params["description"] = description
    if uploaded_by:
        params["uploaded_by"] = uploaded_by
    if tags:
        params["tags"] = tags
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/evidence/upload",
            params=params,
            files={"file": (file.filename, content, file.content_type)},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/evidence")
async def list_evidence(
    engagement_id: Optional[str] = Query(None),
    evidence_type: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
):
    s = get_settings()
    params = {}
    if engagement_id:
        params["engagement_id"] = engagement_id
    if evidence_type:
        params["evidence_type"] = evidence_type
    if tags:
        params["tags"] = tags
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/evidence",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/evidence/{eid}")
async def get_evidence(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/evidence/{eid}",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/evidence/{eid}/content")
async def get_evidence_content(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.get(
            f"{s.rag_api_url}/evidence/{eid}/content",
            headers={"x-api-key": s.api_key},
        )
        return StreamingResponse(
            io.BytesIO(resp.content),
            media_type=resp.headers.get("content-type", "application/octet-stream"),
        )


@router.get("/api/evidence/{eid}/thumbnail")
async def get_evidence_thumbnail(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/evidence/{eid}/thumbnail",
            headers={"x-api-key": s.api_key},
        )
        return StreamingResponse(
            io.BytesIO(resp.content),
            media_type="image/png",
        )


@router.post("/api/evidence/{eid}/link")
async def link_evidence(
    eid: str,
    entity_type: str = Query(...),
    entity_id: str = Query(...),
):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/evidence/{eid}/link",
            params={"entity_type": entity_type, "entity_id": entity_id},
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/findings/{source}/{fid}/evidence")
async def get_finding_evidence(source: str, fid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/findings/{source}/{fid}/evidence",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.delete("/api/evidence/{eid}")
async def delete_evidence(eid: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/evidence/{eid}",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)
