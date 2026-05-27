"""BFF proxy router for API Collections + Test Sessions (Swagger/OpenAPI)."""

from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException, Query, UploadFile, File
from pydantic import BaseModel
from config import get_settings
from utils import safe_json

router = APIRouter()


# --- Models ---

class TestSessionCreate(BaseModel):
    name: Optional[str] = None
    collection_id: Optional[str] = None
    jwt_token: Optional[str] = None
    proxy_url: Optional[str] = None
    variables: Optional[dict] = None


class TestSessionUpdate(BaseModel):
    name: Optional[str] = None
    jwt_token: Optional[str] = None
    proxy_url: Optional[str] = None
    variables: Optional[dict] = None


class TestExecute(BaseModel):
    session_id: str
    endpoint_id: str
    params: Optional[dict] = None
    body: Optional[dict] = None
    headers: Optional[dict] = None


class SendToPipeline(BaseModel):
    collection_id: str
    target_url: Optional[str] = None


class RunAll(BaseModel):
    session_id: str
    collection_id: str
    variables: Optional[dict] = None
    headers: Optional[dict] = None


class AuthCapture(BaseModel):
    login_url: str
    mode: str = "client_credentials"
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    token_patterns: Optional[list] = None
    wait_seconds: int = 30
    extra_params: Optional[dict] = None


# --- Models (import-url) ---

class ImportUrl(BaseModel):
    url: str


class CollectionToScope(BaseModel):
    scope_name: str


# --- API Collection Endpoints ---

@router.post("/api/api-collections/import-url")
async def import_swagger_url(body: ImportUrl):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-collections/import-url",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/api-collections/import")
async def import_swagger_file(file: UploadFile = File(...)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-collections/import",
            files={"file": (file.filename, await file.read(), file.content_type or "application/json")},
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/api-collections/import-dir")
async def import_swagger_dir():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-collections/import-dir",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/api-collections")
async def list_collections():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-collections",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.get("/api/api-collections/{collection_id}")
async def get_collection(collection_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-collections/{collection_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/api-collections/{collection_id}")
async def delete_collection(collection_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/api-collections/{collection_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/api-collections/{collection_id}/endpoints")
async def list_endpoints(
    collection_id: str,
    method: Optional[str] = Query(None),
    tag: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
):
    s = get_settings()
    params = {}
    if method:
        params["method"] = method
    if tag:
        params["tag"] = tag
    if search:
        params["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-collections/{collection_id}/endpoints",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


# --- Test Session Endpoints ---

@router.post("/api/api-test/sessions")
async def create_session(body: TestSessionCreate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-test/sessions",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/api-test/sessions")
async def list_sessions():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-test/sessions",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.patch("/api/api-test/sessions/{session_id}")
async def update_session(session_id: str, body: TestSessionUpdate):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/api-test/sessions/{session_id}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/api-test/sessions/{session_id}")
async def delete_session(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/api-test/sessions/{session_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/api-test/execute")
async def execute_test(body: TestExecute):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-test/execute",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/api-test/sessions/{session_id}/history")
async def get_history(
    session_id: str,
    endpoint_id: Optional[str] = Query(None),
    limit: int = Query(50),
):
    s = get_settings()
    params = {"limit": limit}
    if endpoint_id:
        params["endpoint_id"] = endpoint_id
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-test/sessions/{session_id}/history",
            params=params,
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/api-test/send-to-pipeline")
async def send_to_pipeline(body: SendToPipeline):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-test/send-to-pipeline",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Auth Capture (proxied to playwright-scanner) ---

@router.post("/api/auth/capture")
async def capture_auth(body: AuthCapture):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=90) as c:
        resp = await c.post(
            f"{s.playwright_scanner_url}/auth/capture",
            json=body.model_dump(exclude_none=True),
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Clear session history ---

@router.delete("/api/api-test/sessions/{session_id}/history")
async def clear_session_history(session_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/api-test/sessions/{session_id}/history",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


# --- Common parameters ---

@router.get("/api/api-collections/{collection_id}/common-params")
async def get_common_params(collection_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-collections/{collection_id}/common-params",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


# --- Param Configs (persist configuration values) ---

class ParamConfigBody(BaseModel):
    name: str
    config: Optional[dict] = None
    auth_header: Optional[str] = None


@router.get("/api/api-collections/{collection_id}/param-configs")
async def list_param_configs(collection_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/api-collections/{collection_id}/param-configs",
            headers={"x-api-key": s.api_key},
        )
        return safe_json(resp)


@router.post("/api/api-collections/{collection_id}/param-configs")
async def create_param_config(collection_id: str, body: ParamConfigBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-collections/{collection_id}/param-configs",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.put("/api/api-param-configs/{config_id}")
async def update_param_config(config_id: str, body: ParamConfigBody):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.put(
            f"{s.rag_api_url}/api-param-configs/{config_id}",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/api-param-configs/{config_id}")
async def delete_param_config(config_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/api-param-configs/{config_id}",
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/api-collections/{collection_id}/param-configs/import")
async def import_param_configs(collection_id: str, body: dict):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-collections/{collection_id}/param-configs/import",
            json=body,
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Add collection endpoints to scope ---

@router.post("/api/api-collections/{collection_id}/to-scope")
async def collection_to_scope(collection_id: str, body: CollectionToScope):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-collections/{collection_id}/to-scope",
            json=body.model_dump(),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# --- Run all endpoints ---

@router.post("/api/api-test/run-all")
async def run_all_endpoints(body: RunAll):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=300) as c:
        resp = await c.post(
            f"{s.rag_api_url}/api-test/run-all",
            json=body.model_dump(exclude_none=True),
            headers={"x-api-key": s.api_key},
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)
