import httpx
from fastapi import APIRouter, HTTPException, UploadFile, File
from config import get_settings
from utils import safe_json

router = APIRouter()


@router.get("/api/wordlists")
async def list_wordlists():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/wordlists",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/wordlists/upload")
async def upload_wordlist(file: UploadFile = File(...), list_type: str = "passwords", description: str = None):
    s = get_settings()
    content = await file.read()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        files = {"file": (file.filename, content, file.content_type or "text/plain")}
        params = {"list_type": list_type}
        if description:
            params["description"] = description
        resp = await c.post(
            f"{s.rag_api_url}/wordlists/upload",
            files=files,
            params=params,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/wordlists/{wordlist_id}")
async def delete_wordlist(wordlist_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/wordlists/{wordlist_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
