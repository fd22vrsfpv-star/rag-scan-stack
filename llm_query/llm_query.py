# llm_query.py
# FastAPI proxy exposing common Ollama endpoints (generate, chat, embeddings, tags, ps, pull, delete, show)
# plus simple health checks. Supports streaming (NDJSON) and pass-through options.
# When LLM_BACKEND=azure, translates Ollama-format requests to Azure OpenAI / AI Foundry API.

import os
import logging
import json
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

LLM_BACKEND = os.environ.get("LLM_BACKEND", "ollama").lower()
AZURE_ENDPOINT = os.environ.get("AZURE_ENDPOINT", "")
AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "")
AZURE_MODEL = os.environ.get("AZURE_MODEL", "")
AZURE_API_VERSION = os.environ.get("AZURE_API_VERSION", "2024-08-01-preview")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

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


def _normalize_model(model: Optional[str]) -> str:
    # Treat common placeholder values as absent and fallback to DEFAULT_MODEL
    if model is None:
        return DEFAULT_MODEL
    name = str(model).strip()
    invalid = {"", "string", "your-model", "<your model>", "<model>", "model", "none", "null"}
    if name.lower() in invalid:
        return DEFAULT_MODEL
    return name


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


# ---------- Azure Helpers ----------

def _azure_chat_url(model: Optional[str] = None) -> str:
    """Build Azure chat completions URL based on endpoint pattern."""
    base = AZURE_ENDPOINT.rstrip("/")
    mdl = model or AZURE_MODEL
    if ".models.ai.azure.com" in base:
        return f"{base}/v1/chat/completions"
    return f"{base}/openai/deployments/{mdl}/chat/completions?api-version={AZURE_API_VERSION}"


def _azure_embed_url(model: Optional[str] = None) -> str:
    """Build Azure embeddings URL."""
    base = AZURE_ENDPOINT.rstrip("/")
    mdl = model or AZURE_MODEL
    if ".models.ai.azure.com" in base:
        return f"{base}/v1/embeddings"
    return f"{base}/openai/deployments/{mdl}/embeddings?api-version={AZURE_API_VERSION}"


def _azure_headers() -> Dict[str, str]:
    return {"api-key": AZURE_API_KEY, "Content-Type": "application/json"}


def _azure_json_post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST to Azure endpoint with API key auth."""
    try:
        r = requests.post(url, json=payload, headers=_azure_headers(), timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("HTTPError posting to Azure")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException posting to Azure")
        raise HTTPException(status_code=502, detail=f"Azure endpoint unreachable: {e}")


# ---------- OpenAI Helpers ----------

def _openai_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}


def _openai_chat_url() -> str:
    return f"{OPENAI_API_BASE.rstrip('/')}/v1/chat/completions"


def _openai_embed_url() -> str:
    return f"{OPENAI_API_BASE.rstrip('/')}/v1/embeddings"


def _openai_json_post(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST to OpenAI endpoint."""
    try:
        r = requests.post(url, json=payload, headers=_openai_headers(), timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("HTTPError posting to OpenAI")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException posting to OpenAI")
        raise HTTPException(status_code=502, detail=f"OpenAI endpoint unreachable: {e}")


# ---------- Anthropic Helpers ----------

def _anthropic_headers() -> Dict[str, str]:
    return {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }


def _anthropic_json_post(payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST to Anthropic messages endpoint."""
    try:
        r = requests.post("https://api.anthropic.com/v1/messages",
                          json=payload, headers=_anthropic_headers(), timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("HTTPError posting to Anthropic")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException posting to Anthropic")
        raise HTTPException(status_code=502, detail=f"Anthropic endpoint unreachable: {e}")


def _anthropic_extract_text(data: Dict) -> str:
    """Extract text content from Anthropic response."""
    for block in data.get("content", []):
        if block.get("type") == "text":
            return block.get("text", "")
    return ""


# ---------- Schemas ----------


class GenerateRequest(BaseModel):
    prompt: str
    model: Optional[str] = Field(default=DEFAULT_MODEL, description="Default LLM model")
    stream: bool = False
    # any extra ollama options (temperature, top_p, seed, mirostat, etc.)
    options: Optional[Dict[str, Any]] = None


class ChatMessage(BaseModel):
    role: str  # "system" | "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = Field(default=DEFAULT_MODEL, description="Default LLM model")
    stream: bool = False
    options: Optional[Dict[str, Any]] = None


class EmbeddingsRequest(BaseModel):
    model: Optional[str] = Field(default=DEFAULT_MODEL, description="Default LLM model")
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


def _determine_running_services(ps: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[str]:
    # Parse the /ps response to determine running services/model names without external dependencies
    names: List[str] = []
    if isinstance(ps, dict):
        items = ps.get("models") or ps.get("processes") or ps.get("running") or []
    elif isinstance(ps, list):
        items = ps
    else:
        items = []

    for item in items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("model") or item.get("id")
            if name:
                names.append(str(name))
        elif isinstance(item, str):
            names.append(item)

    return names


def _get_port_scan_results(json_data: Dict[str, Any]) -> Dict[str, Any]:
    # Placeholder function to fetch port scan results from JSON input
    # Replace with actual logic to parse and return port scan results
    return json_data

@router.get("/health", response_model=HealthResponse)


def health():
    if LLM_BACKEND == "azure":
        try:
            url = _azure_chat_url()
            r = requests.post(
                url,
                json={"messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
                headers=_azure_headers(), timeout=10,
            )
            r.raise_for_status()
            return HealthResponse(
                ok=True, endpoint=AZURE_ENDPOINT,
                models=[{"name": AZURE_MODEL, "backend": "azure"}],
                running=[AZURE_MODEL],
            )
        except Exception as e:
            logger.error(f"Azure health check failed: {e}")
            return HealthResponse(
                ok=False, endpoint=AZURE_ENDPOINT, models=[], running=[], detail=str(e),
            )

    if LLM_BACKEND == "openai":
        try:
            r = requests.post(
                _openai_chat_url(),
                json={"model": OPENAI_MODEL, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
                headers=_openai_headers(), timeout=10,
            )
            r.raise_for_status()
            return HealthResponse(
                ok=True, endpoint=OPENAI_API_BASE,
                models=[{"name": OPENAI_MODEL, "backend": "openai"}],
                running=[OPENAI_MODEL],
            )
        except Exception as e:
            logger.error(f"OpenAI health check failed: {e}")
            return HealthResponse(ok=False, endpoint=OPENAI_API_BASE, models=[], running=[], detail=str(e))

    if LLM_BACKEND == "anthropic":
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                json={"model": ANTHROPIC_MODEL, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]},
                headers=_anthropic_headers(), timeout=10,
            )
            r.raise_for_status()
            return HealthResponse(
                ok=True, endpoint="https://api.anthropic.com",
                models=[{"name": ANTHROPIC_MODEL, "backend": "anthropic"}],
                running=[ANTHROPIC_MODEL],
            )
        except Exception as e:
            logger.error(f"Anthropic health check failed: {e}")
            return HealthResponse(ok=False, endpoint="https://api.anthropic.com", models=[], running=[], detail=str(e))

    base = _api_base()
    try:
        tags = _json_get(_endpoint("/tags"))
        ps = _json_get(_endpoint("/ps"))
        models = tags.get("models", tags if isinstance(tags, list) else [])
        running = _determine_running_services(ps)
        return HealthResponse(ok=True, endpoint=base, models=models, running=running)
    except HTTPException as e:
        return HealthResponse(ok=False, endpoint=base, models=[], running=[], detail=str(e.detail))
    except Exception as e:
        logger.exception("Unexpected error in /health")
        return HealthResponse(ok=False, endpoint=base, models=[], running=[], detail=str(e))

@router.get("/tags")


def tags():
    if LLM_BACKEND == "azure":
        return {"models": [{"name": AZURE_MODEL, "backend": "azure"}]}
    if LLM_BACKEND == "openai":
        return {"models": [{"name": OPENAI_MODEL, "backend": "openai"}]}
    if LLM_BACKEND == "anthropic":
        return {"models": [{"name": ANTHROPIC_MODEL, "backend": "anthropic"}]}
    return _json_get(_endpoint("/tags"))

@router.get("/ps")


def ps():
    if LLM_BACKEND == "azure":
        return {"models": [{"name": AZURE_MODEL, "backend": "azure"}]}
    return _json_get(_endpoint("/ps"))

@router.post("/generate")


def generate(req: GenerateRequest):
    if LLM_BACKEND == "azure":
        model = AZURE_MODEL or _normalize_model(req.model)
        payload: Dict[str, Any] = {
            "messages": [{"role": "user", "content": req.prompt}],
            "max_tokens": 2048,
        }
        if req.options:
            if "temperature" in req.options:
                payload["temperature"] = req.options["temperature"]
            if "top_p" in req.options:
                payload["top_p"] = req.options["top_p"]
        url = _azure_chat_url(model)
        data = _azure_json_post(url, payload)
        content = data["choices"][0]["message"]["content"]
        return JSONResponse(content={"model": model, "response": content, "done": True})

    if LLM_BACKEND == "openai":
        model = OPENAI_MODEL
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": req.prompt}],
            "max_tokens": 2048,
        }
        if req.options:
            if "temperature" in req.options:
                payload["temperature"] = req.options["temperature"]
        data = _openai_json_post(_openai_chat_url(), payload)
        content = data["choices"][0]["message"]["content"]
        return JSONResponse(content={"model": model, "response": content, "done": True})

    if LLM_BACKEND == "anthropic":
        model = ANTHROPIC_MODEL
        payload = {
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": req.prompt}],
        }
        data = _anthropic_json_post(payload)
        content = _anthropic_extract_text(data)
        return JSONResponse(content={"model": model, "response": content, "done": True})

    payload_ollama: Dict[str, Any] = {
        "model": _normalize_model(req.model),
        "prompt": req.prompt,
        "stream": req.stream,
    }
    if req.options:
        payload_ollama.update(req.options)

    url = _endpoint("/generate")
    if req.stream:
        gen = _stream_post(url, payload_ollama)
        return StreamingResponse(gen, media_type="application/x-ndjson")
    else:
        data = _json_post(url, payload_ollama)
        return JSONResponse(content=data)

@router.post("/chat")


def chat(req: ChatRequest):
    if LLM_BACKEND == "azure":
        model = AZURE_MODEL or _normalize_model(req.model)
        payload: Dict[str, Any] = {
            "messages": [m.dict() for m in req.messages],
            "max_tokens": 2048,
        }
        if req.options:
            if "temperature" in req.options:
                payload["temperature"] = req.options["temperature"]
            if "top_p" in req.options:
                payload["top_p"] = req.options["top_p"]
        url = _azure_chat_url(model)
        data = _azure_json_post(url, payload)
        content = data["choices"][0]["message"]["content"]
        return JSONResponse(content={
            "model": model,
            "message": {"role": "assistant", "content": content},
            "done": True,
        })

    if LLM_BACKEND == "openai":
        model = OPENAI_MODEL
        payload = {
            "model": model,
            "messages": [m.dict() for m in req.messages],
            "max_tokens": 2048,
        }
        if req.options:
            if "temperature" in req.options:
                payload["temperature"] = req.options["temperature"]
        data = _openai_json_post(_openai_chat_url(), payload)
        content = data["choices"][0]["message"]["content"]
        return JSONResponse(content={
            "model": model,
            "message": {"role": "assistant", "content": content},
            "done": True,
        })

    if LLM_BACKEND == "anthropic":
        model = ANTHROPIC_MODEL
        # Extract system messages for Anthropic
        msgs = [m.dict() for m in req.messages]
        system_parts = [m["content"] for m in msgs if m.get("role") == "system"]
        filtered = [m for m in msgs if m.get("role") != "system"]
        payload: Dict[str, Any] = {
            "model": model,
            "max_tokens": 2048,
            "messages": filtered,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        data = _anthropic_json_post(payload)
        content = _anthropic_extract_text(data)
        return JSONResponse(content={
            "model": model,
            "message": {"role": "assistant", "content": content},
            "done": True,
        })

    payload_ollama: Dict[str, Any] = {
        "model": _normalize_model(req.model),
        "messages": [m.dict() for m in req.messages],
        "stream": req.stream,
    }
    if req.options:
        payload_ollama.update(req.options)

    url = _endpoint("/chat")
    if req.stream:
        gen = _stream_post(url, payload_ollama)
        return StreamingResponse(gen, media_type="application/x-ndjson")
    else:
        data = _json_post(url, payload_ollama)
        return JSONResponse(content=data)

@router.post("/embeddings")


def embeddings(req: EmbeddingsRequest):
    if LLM_BACKEND == "azure":
        model = AZURE_MODEL or _normalize_model(req.model)
        text = req.prompt or req.input or ""
        url = _azure_embed_url(model)
        data = _azure_json_post(url, {"input": text, "model": model})
        embedding = data["data"][0]["embedding"]
        return JSONResponse(content={"embedding": embedding})

    if LLM_BACKEND == "openai":
        model = OPENAI_MODEL
        text = req.prompt or req.input or ""
        data = _openai_json_post(_openai_embed_url(), {"input": text, "model": model})
        embedding = data["data"][0]["embedding"]
        return JSONResponse(content={"embedding": embedding})

    if LLM_BACKEND == "anthropic":
        # Anthropic has no embeddings API — return 501
        raise HTTPException(
            status_code=501,
            detail="Anthropic does not provide an embeddings API. Use the local sentence-transformers embedder instead.",
        )

    payload: Dict[str, Any] = {
        "model": _normalize_model(req.model),
    }
    if req.prompt is not None:
        payload["prompt"] = req.prompt
    if req.input is not None:
        payload["input"] = req.input

    return _json_post(_endpoint("/embeddings"), payload)

@router.post("/pull")


def pull(req: PullRequest):
    if LLM_BACKEND == "azure":
        return JSONResponse(content={
            "status": "not applicable for Azure backend",
            "model": req.model,
        })
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
    if LLM_BACKEND == "azure":
        return JSONResponse(content={
            "status": "not applicable for Azure backend",
            "model": req.model,
        })
    payload = {"name": req.model}
    return _json_post(_endpoint("/delete"), payload)

@router.post("/show")


def show(req: ShowRequest):
    if LLM_BACKEND == "azure":
        return JSONResponse(content={
            "modelfile": f"Azure deployment: {AZURE_MODEL}",
            "parameters": f"endpoint={AZURE_ENDPOINT}",
            "template": "",
            "details": {"backend": "azure", "model": AZURE_MODEL},
        })
    payload = {"name": req.model}
    return _json_post(_endpoint("/show"), payload)

# Back-compat alias for "query" -> generate

@router.post("/query")


def legacy_query(req: GenerateRequest):
    return generate(req)

@router.post("/install")


def install(req: PullRequest):
    if LLM_BACKEND == "azure":
        return JSONResponse(content={
            "status": "not applicable for Azure backend",
            "model": req.model,
        })
    # Convenience endpoint to install (pull) a specific model
    payload: Dict[str, Any] = {"name": _normalize_model(req.model)}
    if req.insecure is not None:
        payload["insecure"] = req.insecure
    if req.stream:
        gen = _stream_post(_endpoint("/pull"), payload)
        return StreamingResponse(gen, media_type="application/x-ndjson")
    else:
        return _json_post(_endpoint("/pull"), payload)

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
