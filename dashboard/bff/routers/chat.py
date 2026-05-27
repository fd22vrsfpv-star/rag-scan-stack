import json
import logging
import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from services.ollama_chat import stream_chat
from config import get_settings
from utils import safe_json

log = logging.getLogger("chat")
router = APIRouter()


class ChatRequest(BaseModel):
    messages: list[dict]
    model: str | None = None
    context: dict | None = None  # Current page context (findings, assets, etc.)
    profile: str | None = None  # Tool profile: recon, web, osint, exploit, analysis, all
    system_prompt: str | None = None  # User-defined system prompt from Settings
    backend: str | None = None  # LLM backend override (openai, anthropic, azure, ollama)
    # Files uploaded by the user (already stored in evidence_store).
    # Each entry: {"id": "<uuid>", "name": "...", "content_type": "...", "size": <int>}
    # The chat service prepends a system note listing them and the LLM can call
    # the `read_uploaded_file` tool with the id to fetch the content.
    attached_files: list[dict] | None = None
    # Per-request tool allowlist — supplied by the saved-query picker so the
    # current chat is restricted to a preset's allowed_tools. Layer 2/3 of
    # the LLM-hardening stack: filters the tool catalog the model sees AND
    # the dispatcher refuses any call outside the list. None = no restriction.
    allowed_tools: list[str] | None = None


async def _resolve_llm_backend(settings) -> str:
    """Read LLM backend from app_settings DB, fallback to env."""
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            resp = await c.get(f"{settings.rag_api_url}/settings/config/llm.backend",
                               headers={"x-api-key": settings.api_key})
            if resp.status_code == 200:
                val = resp.json().get("value", "").strip()
                if val:
                    return val
    except Exception:
        pass
    return settings.llm_backend


async def _resolve_llm_keys(settings, backend: str) -> dict:
    """Read LLM API keys from app_settings DB for the given backend."""
    keys = {}
    key_map = {
        "openai": ["llm.openai_api_key", "llm.openai_model"],
        "anthropic": ["llm.anthropic_api_key", "llm.anthropic_model"],
        "azure": ["llm.azure_api_key", "llm.azure_endpoint", "llm.azure_model"],
    }
    db_keys = key_map.get(backend, [])
    if not db_keys:
        return keys
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            for k in db_keys:
                resp = await c.get(f"{settings.rag_api_url}/settings/config/{k}",
                                   headers={"x-api-key": settings.api_key})
                if resp.status_code == 200:
                    val = resp.json().get("value", "")
                    if val:
                        keys[k.replace("llm.", "")] = val
    except Exception:
        pass
    return keys


@router.post("/api/chat")
async def chat(req: ChatRequest):
    settings = get_settings()

    # Resolve backend: request override > DB setting > env var
    backend = req.backend
    if not backend:
        backend = await _resolve_llm_backend(settings)

    # Read API keys from DB for non-Ollama backends
    db_keys = await _resolve_llm_keys(settings, backend)

    # Temporarily override settings for this request
    orig_backend = settings.llm_backend
    orig_openai_key = settings.openai_api_key
    orig_openai_model = settings.openai_model
    orig_anthropic_key = settings.anthropic_api_key
    orig_anthropic_model = settings.anthropic_model
    orig_azure_key = settings.azure_api_key
    orig_azure_endpoint = settings.azure_endpoint
    orig_azure_model = settings.azure_model

    settings.llm_backend = backend
    if db_keys.get("openai_api_key"):
        settings.openai_api_key = db_keys["openai_api_key"]
    if db_keys.get("openai_model"):
        settings.openai_model = db_keys["openai_model"]
    if db_keys.get("anthropic_api_key"):
        settings.anthropic_api_key = db_keys["anthropic_api_key"]
    if db_keys.get("anthropic_model"):
        settings.anthropic_model = db_keys["anthropic_model"]
    if db_keys.get("azure_api_key"):
        settings.azure_api_key = db_keys["azure_api_key"]
    if db_keys.get("azure_endpoint"):
        settings.azure_endpoint = db_keys["azure_endpoint"]
    if db_keys.get("azure_model"):
        settings.azure_model = db_keys["azure_model"]

    model = req.model or settings.ollama_model

    async def event_generator():
        try:
            async for event in stream_chat(
                messages=req.messages,
                model=model,
                context=req.context,
                profile=req.profile or "recon",
                user_system_prompt=req.system_prompt,
                attached_files=req.attached_files or [],
                allowed_tools=req.allowed_tools,
            ):
                yield {"event": event["type"], "data": json.dumps(event["data"])}
        finally:
            # Restore original settings
            settings.llm_backend = orig_backend
            settings.openai_api_key = orig_openai_key
            settings.openai_model = orig_openai_model
            settings.anthropic_api_key = orig_anthropic_key
            settings.anthropic_model = orig_anthropic_model
            settings.azure_api_key = orig_azure_key
            settings.azure_endpoint = orig_azure_endpoint
            settings.azure_model = orig_azure_model

    return EventSourceResponse(event_generator())
