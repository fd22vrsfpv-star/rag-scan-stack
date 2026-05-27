# llm_query.py
# FastAPI proxy exposing common Ollama endpoints (generate, chat, embeddings, tags, ps, pull, delete, show)
# plus simple health checks. Supports streaming (NDJSON) and pass-through options.

import os
import json
import logging
from typing import Any, Dict, List, Optional, Iterator, Union

import requests
from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------- Config / Logging ----------
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("llm-query")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:14b")
REQUEST_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "120"))

# ---------- App ----------
app = FastAPI(title="LLM Query (Ollama Proxy)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter(prefix="/ollama")
# ---------- Helpers ----------
def _api_base() -> str:
    return OLLAMA_URL.rstrip("/") + "/api"

def _endpoint(path: str) -> str:
    return _api_base() + path

def _http_error_from_requests(e: requests.HTTPError, fallback_status: int = 502) -> HTTPException:
    status = getattr(e.response, "status_code", fallback_status)
    try:
        detail = e.response.json()
    except Exception:
        detail = getattr(e.response, "text", str(e))
    return HTTPException(status_code=status, detail=detail)

def _stream_post(url: str, payload: Dict[str, Any]) -> Iterator[bytes]:
    try:
        with requests.post(url, json=payload, stream=True, timeout=REQUEST_TIMEOUT) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                # passthrough NDJSON exactly as Ollama emits
                yield line + b"\n"
    except requests.HTTPError as e:
        logger.exception("HTTPError streaming from Ollama")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException streaming from Ollama")
        raise HTTPException(status_code=502, detail=f"Ollama unreachable: {e}")

def _json_post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("HTTPError posting to Ollama")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException posting to Ollama")
        raise HTTPException(status_code=502, detail=f"Ollama unreachable: {e}")

def _json_get(url: str) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("HTTPError getting from Ollama")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException getting from Ollama")
        raise HTTPException(status_code=502, detail=f"Ollama unreachable: {e}")

# ---------- Schemas ----------
class GenerateRequest(BaseModel):
    prompt: str
    model: Optional[str] = None
    stream: bool = False
    # any extra ollama options (temperature, top_p, seed, mirostat, etc.)
    options: Optional[Dict[str, Any]] = None

class ChatMessage(BaseModel):
    role: str  # "system" | "user" | "assistant"
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = None
    stream: bool = False
    options: Optional[Dict[str, Any]] = None

class EmbeddingsRequest(BaseModel):
    model: Optional[str] = None
    prompt: Optional[str] = None
    input: Optional[str] = None

class PullRequest(BaseModel):
    model: str
    insecure: Optional[bool] = None
    stream: bool = False

class DeleteRequest(BaseModel):
    model: str

class ShowRequest(BaseModel):
    model: str

class HealthResponse(BaseModel):
    ok: bool
    endpoint: str
    models: List[Any] = Field(default_factory=list)
    running: List[Any] = Field(default_factory=list)
    detail: Optional[str] = None

# ---------- Endpoints ----------
@router.get("/health", response_model=HealthResponse)
def health():
    base = _api_base()
    try:
        tags = _json_get(_endpoint("/tags"))
        ps = _json_get(_endpoint("/ps"))
        models = tags.get("models", tags if isinstance(tags, list) else [])
        running = ps.get("models", ps if isinstance(ps, list) else [])
        return HealthResponse(ok=True, endpoint=base, models=models, running=running)
    except HTTPException as e:
        return HealthResponse(ok=False, endpoint=base, models=[], running=[], detail=str(e.detail))
    except Exception as e:
        logger.exception("Unhandled error in /health")
        return HealthResponse(ok=False, endpoint=base, models=[], running=[], detail=str(e))

@router.get("/tags")
def tags():
    return _json_get(_endpoint("/tags"))

@router.get("/ps")
def ps():
    return _json_get(_endpoint("/ps"))

@router.post("/generate")
def generate(req: GenerateRequest):
    payload: Dict[str, Any] = {
        "model": req.model or DEFAULT_MODEL,
        "prompt": req.prompt,
        "stream": req.stream,
    }
    if req.options:
        payload.update(req.options)

    url = _endpoint("/generate")
    if req.stream:
        gen = _stream_post(url, payload)
        return StreamingResponse(gen, media_type="application/x-ndjson")
    else:
        data = _json_post(url, payload)
        return JSONResponse(content=data)

@router.post("/chat")
def chat(req: ChatRequest):
    payload: Dict[str, Any] = {
        "model": req.model or DEFAULT_MODEL,
        "messages": [m.dict() for m in req.messages],
        "stream": req.stream,
    }
    if req.options:
        payload.update(req.options)

    url = _endpoint("/chat")
    if req.stream:
        gen = _stream_post(url, payload)
        return StreamingResponse(gen, media_type="application/x-ndjson")
    else:
        data = _json_post(url, payload)
        return JSONResponse(content=data)

@router.post("/embeddings")
def embeddings(req: EmbeddingsRequest):
    payload: Dict[str, Any] = {
        "model": req.model or DEFAULT_MODEL,
    }
    if req.prompt is not None:
        payload["prompt"] = req.prompt
    if req.input is not None:
        payload["input"] = req.input

    return _json_post(_endpoint("/embeddings"), payload)

@router.post("/pull")
def pull(req: PullRequest):
    payload: Dict[str, Any] = {"name": req.model}
    if req.insecure is not None:
        payload["insecure"] = req.insecure
    if req.stream:
        gen = _stream_post(_endpoint("/pull"), payload)
        return StreamingResponse(gen, media_type="application/x-ndjson")
    else:
        return _json_post(_endpoint("/pull"), payload)

@router.post("/delete")
def delete(req: DeleteRequest):
    payload = {"name": req.model}
    return _json_post(_endpoint("/delete"), payload)

@router.post("/show")
def show(req: ShowRequest):
    payload = {"name": req.model}
    return _json_post(_endpoint("/show"), payload)

# Back-compat alias for "query" -> generate
@router.post("/query")
def legacy_query(req: GenerateRequest):
    return generate(req)

# Root-level kube-style health
@app.get("/healthz", response_model=HealthResponse)
def root_health():
    return health()

# Mount router
app.include_router(router)

# ---------- Local dev ----------
if __name__ == "__main__":
    # Run: OLLAMA_URL=http://localhost:11434 uvicorn llm_query:app --host 0.0.0.0 --port 8000
    import uvicorn
    uvicorn.run("llm_query:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), reload=False)
