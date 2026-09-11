# llm_query.py
# FastAPI proxy exposing common Ollama endpoints (generate, chat, embeddings, tags, ps, pull, delete, show)
# plus simple health checks. Supports streaming (NDJSON) and pass-through options.
# When LLM_BACKEND=azure, translates Ollama-format requests to Azure OpenAI / AI Foundry API.

import os
import time
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

# Live config: dashboard Settings -> LLM Tuning (DB llm.*) over env. See
# llm_settings.py. _refresh_llm_globals() repopulates the constants above from
# the resolver before each request (via middleware), so the GUI drives this
# proxy without a container recreate.
try:
    from common.llm_settings import get_llm_settings
except Exception:
    get_llm_settings = None


def _refresh_llm_globals():
    if get_llm_settings is None:
        return
    global LLM_BACKEND, OPENAI_API_BASE, OPENAI_MODEL, OPENAI_API_KEY
    global AZURE_ENDPOINT, AZURE_MODEL, AZURE_API_KEY, AZURE_API_VERSION
    global ANTHROPIC_API_KEY, ANTHROPIC_MODEL
    try:
        s = get_llm_settings()
    except Exception:
        return
    LLM_BACKEND = (s.get("backend") or LLM_BACKEND).lower()
    OPENAI_API_BASE = s.get("openai_api_base") or OPENAI_API_BASE
    OPENAI_MODEL = s.get("openai_model") or OPENAI_MODEL
    OPENAI_API_KEY = s.get("openai_api_key") or OPENAI_API_KEY
    AZURE_ENDPOINT = s.get("azure_endpoint") or AZURE_ENDPOINT
    AZURE_MODEL = s.get("azure_model") or AZURE_MODEL
    AZURE_API_KEY = s.get("azure_api_key") or AZURE_API_KEY
    AZURE_API_VERSION = s.get("azure_api_version") or AZURE_API_VERSION
    ANTHROPIC_API_KEY = s.get("anthropic_api_key") or ANTHROPIC_API_KEY
    ANTHROPIC_MODEL = s.get("anthropic_model") or ANTHROPIC_MODEL


# ---------- App ----------
app = FastAPI(title="LLM Query (Ollama Proxy)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _llm_settings_mw(request, call_next):
    # Pull the latest LLM settings (DB over env) before handling each request.
    try:
        _refresh_llm_globals()
    except Exception:
        pass
    return await call_next(request)


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

def _azure_is_foundry(base: str) -> bool:
    """True for a Microsoft Foundry OpenAI-compatible endpoint (…/openai/v1)."""
    b = base.lower()
    return (".services.ai.azure.com" in b or "/openai/v1" in b
            or b.rstrip("/").endswith("/openai"))


def _azure_foundry_root(base: str) -> str:
    """Resource root for a Foundry endpoint, however it was typed.

    Handles …, …/openai, …/openai/v1, …/openai/v1/chat/completions,
    …/openai/v1/responses (the Responses-API URL the portal shows, which is
    NOT what this stack speaks) and …/api/projects/<name> (a Foundry PROJECT
    endpoint). Each of those is something an operator can legitimately paste;
    without stripping them the built URL doubles up and returns 400/404.
    """
    import re
    b = base.rstrip('/')
    b = re.sub(r'/api/projects/[^/]+/?$', '', b, flags=re.I)
    return re.sub(
        r'(/openai)?(/v1)?(/chat/completions|/embeddings|/responses|/deployments)?/?$',
        '', b.rstrip('/'), flags=re.I).rstrip('/')


def _azure_chat_url(model: Optional[str] = None,
                    endpoint: Optional[str] = None) -> str:
    """Build Azure chat completions URL based on endpoint pattern.

    `endpoint` overrides the global one so a named provider instance targets
    its own resource.
    """
    base = (endpoint or AZURE_ENDPOINT).rstrip("/")
    mdl = model or AZURE_MODEL
    if _azure_is_foundry(base):
        # OpenAI-compatible: model goes in the body (see _azure_json_post).
        return f"{_azure_foundry_root(base)}/openai/v1/chat/completions"
    if ".models.ai.azure.com" in base:
        return f"{base}/v1/chat/completions"
    return f"{base}/openai/deployments/{mdl}/chat/completions?api-version={AZURE_API_VERSION}"


def _azure_embed_url(model: Optional[str] = None) -> str:
    """Build Azure embeddings URL."""
    base = AZURE_ENDPOINT.rstrip("/")
    mdl = model or AZURE_MODEL
    if _azure_is_foundry(base):
        return f"{_azure_foundry_root(base)}/openai/v1/embeddings"
    if ".models.ai.azure.com" in base:
        return f"{base}/v1/embeddings"
    return f"{base}/openai/deployments/{mdl}/embeddings?api-version={AZURE_API_VERSION}"


def _azure_headers(api_key: Optional[str] = None) -> Dict[str, str]:
    """Auth for one Azure call. `api_key` lets a named provider instance use
    its OWN key instead of the global one -- required for two Azure resources
    to be usable at the same time."""
    return {"api-key": api_key or AZURE_API_KEY,
            "Content-Type": "application/json"}


def _caller_model(m):
    """The model the caller asked for, or "" when it left the choice to us.

    Consumers that do not care send "" (or omit it) and get the operator's
    configured default; consumers that DO care -- news enrichment on a cheap
    or local model, agents on a strong one -- name their own. An empty value
    must stay empty rather than defaulting here, or "I don't care" and
    "I want X" become indistinguishable one layer down.
    """
    m = (m or "").strip()
    return _normalize_model(m) if m else ""


# 429 backoff. Azure Foundry quota is per-deployment TPM, so a burst gets
# RateLimitReached and the correct response is to wait, not to fail. This is
# the single chokepoint every non-agent service reaches Azure through, so one
# implementation here covers news, scan-recommender and anything added later.
# The agents keep their own governor because they talk to Azure directly via
# langchain (see autogen_agents/langgraph_engine.py::_RateLimitGovernor).
LLM_429_MAX_RETRIES = int(os.environ.get("LLM_429_MAX_RETRIES") or 3)
LLM_429_BASE_WAIT = float(os.environ.get("LLM_429_BASE_WAIT") or 5)
LLM_429_MAX_WAIT = float(os.environ.get("LLM_429_MAX_WAIT") or 60)


def _retry_after_seconds(resp):
    """The provider's stated cool-down, if it gave one. Honouring what the
    server says beats guessing at it."""
    for h in ("retry-after", "Retry-After", "x-ratelimit-reset-requests"):
        v = (resp.headers or {}).get(h)
        if not v:
            continue
        try:
            return max(0.0, float(str(v).rstrip("s")))
        except (TypeError, ValueError):
            continue
    return None


def _post_with_429_retry(url: str, payload: Dict[str, Any],
                         headers: Dict[str, str]):
    """POST, retrying ONLY on 429.

    Every other status is returned untouched for the caller's normal error
    mapping: a 400 is a contract bug and retrying it just burns more quota.
    """
    wait = LLM_429_BASE_WAIT
    resp = None
    for attempt in range(LLM_429_MAX_RETRIES + 1):
        resp = requests.post(url, json=payload, headers=headers,
                             timeout=REQUEST_TIMEOUT)
        if resp.status_code != 429:
            return resp
        if attempt == LLM_429_MAX_RETRIES:
            logger.warning("429 from %s after %s attempts - giving up",
                           url, attempt + 1)
            return resp
        server = _retry_after_seconds(resp)
        sleep_for = min(server if server is not None else wait, LLM_429_MAX_WAIT)
        logger.warning("429 from %s (attempt %s/%s) - waiting %.1fs%s",
                       url, attempt + 1, LLM_429_MAX_RETRIES + 1, sleep_for,
                       " (server Retry-After)" if server is not None else "")
        time.sleep(sleep_for)
        wait = min(wait * 2, LLM_429_MAX_WAIT)
    return resp


def _azure_json_post(url: str, payload: Dict[str, Any],
                     api_key: Optional[str] = None) -> Dict[str, Any]:
    """POST to Azure endpoint with API key auth."""
    # OpenAI-compatible Azure endpoints (Foundry /openai/v1, models.ai.azure.com)
    # take the model in the BODY; classic deployment URLs carry it in the path
    # (their URL ends with ?api-version=…, so this correctly skips them).
    if url.endswith("/chat/completions"):
        # Only fill the model in when the caller did not set one -- this used to
        # overwrite it unconditionally, discarding the per-request model that
        # generate()/chat() had just resolved.
        payload = {**payload, "model": payload.get("model") or AZURE_MODEL}
    try:
        r = _post_with_429_retry(url, payload, _azure_headers(api_key))
        # The gpt-5 / o-series families REJECT `max_tokens` and require
        # `max_completion_tokens`; older deployments accept only `max_tokens`.
        # Rather than maintain a model list that goes stale, swap the parameter
        # once when the provider tells us to. Verified against gpt-5-mini:
        # max_tokens -> 400 unsupported_parameter, max_completion_tokens -> 200.
        if r.status_code == 400 and "max_tokens" in payload:
            body = (r.text or "")
            if "max_completion_tokens" in body:
                retry = {k: v for k, v in payload.items() if k != "max_tokens"}
                retry["max_completion_tokens"] = payload["max_tokens"]
                logger.info("retrying %s with max_completion_tokens (model %r "
                            "rejects max_tokens)", url, payload.get("model"))
                r = _post_with_429_retry(url, retry, _azure_headers(api_key))
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.exception("HTTPError posting to Azure")
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        logger.exception("RequestException posting to Azure")
        raise HTTPException(status_code=502, detail=f"Azure endpoint unreachable: {e}")


# ---------- OpenAI Helpers ----------

def _openai_headers(api_key: Optional[str] = None) -> Dict[str, str]:
    """`api_key` lets a named provider instance use its own key."""
    return {"Authorization": f"Bearer {api_key or OPENAI_API_KEY}",
            "Content-Type": "application/json"}


def _openai_chat_url(base: Optional[str] = None) -> str:
    return f"{(base or OPENAI_API_BASE).rstrip('/')}/v1/chat/completions"


def _openai_embed_url() -> str:
    return f"{OPENAI_API_BASE.rstrip('/')}/v1/embeddings"


def _openai_json_post(url: str, payload: Dict[str, Any],
                      api_key: Optional[str] = None) -> Dict[str, Any]:
    """POST to OpenAI endpoint."""
    try:
        # 429 retry here too: OpenAI-compatible endpoints rate-limit the same
        # way, and this is the same chokepoint.
        r = _post_with_429_retry(url, payload, _openai_headers(api_key))
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
    # Per-task routing. Naming a task ("news", "exploit", ...) lets the operator
    # choose that task's model AND backend in Settings -> LLM Tuning without the
    # caller knowing anything about models. An explicit `model` still wins, and
    # no task at all behaves exactly as before.
    task: Optional[str] = Field(default=None, description="Routing task name")
    stream: bool = False
    # any extra ollama options (temperature, top_p, seed, mirostat, etc.)
    options: Optional[Dict[str, Any]] = None


class ChatMessage(BaseModel):
    role: str  # "system" | "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = Field(default=DEFAULT_MODEL, description="Default LLM model")
    task: Optional[str] = Field(default=None, description="Routing task name")
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
                json={"model": AZURE_MODEL, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
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

def _route_for(task: Optional[str], explicit_model: Optional[str]):
    """Resolve (backend, model, fallback) for this request.

    Precedence: an explicit `model` from the caller wins outright -- a service
    that names a model has already decided. Otherwise the task's route decides.
    With neither, the active globals apply, i.e. today's behaviour.
    """
    caller = _caller_model(explicit_model)
    if caller:
        return {"backend": LLM_BACKEND, "model": caller,
                "source": "caller", "fallback": None}
    if not task or get_llm_settings is None:
        return {"backend": LLM_BACKEND, "model": AZURE_MODEL or DEFAULT_MODEL,
                "source": "global", "fallback": None}
    try:
        from common.llm_settings import get_route
        r = get_route(task)
        logger.info("route task=%s -> %s:%s (%s)",
                    task, r["backend"], r["model"], r["source"])
        return r
    except Exception as e:
        # Routing must never take the LLM path down; fall back to the globals.
        logger.warning("route lookup for task=%r failed (%s); using globals",
                       task, e)
        return {"backend": LLM_BACKEND, "model": AZURE_MODEL or DEFAULT_MODEL,
                "source": "global", "fallback": None}


def _generate_text(backend: str, model: str, prompt: str,
                   options: Optional[Dict[str, Any]],
                   endpoint: Optional[str] = None,
                   api_key: Optional[str] = None) -> str:
    """One prompt -> text, on an EXPLICITLY named backend and model.

    Separate from generate() so a route can send a request to a backend other
    than the globally-selected one -- that is what makes "news on a local
    ollama while the agents stay on Azure" possible.
    """
    backend = (backend or "").lower()
    temp = (options or {}).get("temperature")
    top_p = (options or {}).get("top_p")

    if backend == "azure":
        payload: Dict[str, Any] = {
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048, "model": model,
        }
        if temp is not None:
            payload["temperature"] = temp
        if top_p is not None:
            payload["top_p"] = top_p
        # endpoint/api_key come from the named provider instance, so two
        # Azure resources can be used side by side.
        data = _azure_json_post(_azure_chat_url(model, endpoint), payload,
                                api_key)
        return data["choices"][0]["message"]["content"]

    if backend == "openai":
        payload = {"model": model,
                   "messages": [{"role": "user", "content": prompt}],
                   "max_tokens": 2048}
        if temp is not None:
            payload["temperature"] = temp
        data = _openai_json_post(_openai_chat_url(endpoint), payload, api_key)
        return data["choices"][0]["message"]["content"]

    if backend == "anthropic":
        data = _anthropic_json_post({
            "model": model, "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        })
        return _anthropic_extract_text(data)

    # ollama / vllm — the native /api/generate shape. The provider's endpoint
    # wins, which is how "news on a local ollama" works while the global
    # OLLAMA_URL still points at a host that does not exist here.
    base = endpoint or OLLAMA_URL
    if not endpoint and backend == "vllm" and get_llm_settings is not None:
        try:
            base = get_llm_settings().get("vllm_url") or base
        except Exception:
            pass
    body: Dict[str, Any] = {"model": model, "prompt": prompt, "stream": False}
    if options:
        body.update(options)
    url = base.rstrip("/") + "/api/generate"
    try:
        r = _post_with_429_retry(url, body, {"Content-Type": "application/json"})
        r.raise_for_status()
        return r.json().get("response", "")
    except requests.HTTPError as e:
        raise _http_error_from_requests(e)
    except requests.RequestException as e:
        # A named provider pointing somewhere unreachable produced a bare 500
        # ("Internal Server Error", no reason) because this branch was the only
        # one without error mapping. Say WHICH provider and WHERE.
        raise HTTPException(
            502,
            f"{backend} endpoint {url} unreachable: {str(e) or type(e).__name__}")


def _generate_routed(route: Dict[str, Any], prompt: str,
                     options: Optional[Dict[str, Any]]):
    """Generate on the route's primary, failing over to its fallback on 429.

    `_post_with_429_retry` has already waited out the provider's Retry-After by
    the time a 429 reaches here, so the quota is genuinely gone and waiting
    longer will not help -- a DIFFERENT model is the only thing that will. The
    response says which one answered, because silently substituting a model the
    operator did not choose would otherwise be invisible.
    """
    primary = (route.get("backend"), route.get("model"))
    try:
        text = _generate_text(primary[0], primary[1], prompt, options,
                              route.get("endpoint"), route.get("api_key"))
        return text, primary, False
    except HTTPException as e:
        fb = route.get("fallback")
        if e.status_code != 429 or not fb:
            # Failover is for 429 ONLY. Anything else is re-raised with the
            # provider and task named: "provider X for task Y said Z" is
            # actionable, a bare status code is not.
            if e.status_code != 429:
                raise HTTPException(
                    e.status_code,
                    f"provider {route.get('provider')!r} (task {route.get('task')!r}): "
                    f"{e.detail}")
            raise
        logger.warning(
            "429 exhausted on %s/%s:%s for task=%s — failing over to %s/%s:%s",
            route.get("provider"), primary[0], primary[1], route.get("task"),
            fb.get("provider"), fb["backend"], fb["model"])
        text = _generate_text(fb["backend"], fb["model"], prompt, options,
                              fb.get("endpoint"), fb.get("api_key"))
        return text, (fb["backend"], fb["model"]), True


@router.post("/generate")


def generate(req: GenerateRequest):
    # Per-task routing takes over whenever the caller names a task. It handles
    # every backend itself (including one different from the global default)
    # and fails over to the task's fallback model on an exhausted 429, so it
    # short-circuits the per-backend branches below.
    if req.task and not req.stream:
        route = _route_for(req.task, req.model)
        text, used, failed_over = _generate_routed(route, req.prompt, req.options)
        return JSONResponse(content={
            "model": used[1], "response": text, "done": True,
            # Diagnostics: which route answered, and whether the primary was
            # skipped. An operator debugging "why does this read like a small
            # model" needs to see a failover happened.
            "backend": used[0],
            "provider": (route.get("fallback") or {}).get("provider")
                        if failed_over else route.get("provider"),
            "task": req.task,
            "route_source": route.get("source"),
            "failed_over": failed_over,
        })

    if LLM_BACKEND == "azure":
        # A model named by the CALLER wins; AZURE_MODEL is only the default.
        # It used to be `AZURE_MODEL or req.model`, so the global model always
        # won and no consumer could pick its own -- which is what made a cheap
        # model for news and a strong one for the agents impossible.
        # NOTE: embeddings() deliberately keeps the old behaviour; its model is
        # a separate deployment and a chat model name there breaks the embedder.
        model = _caller_model(req.model) or AZURE_MODEL
        payload: Dict[str, Any] = {
            "messages": [{"role": "user", "content": req.prompt}],
            "max_tokens": 2048,
        }
        if req.options:
            if "temperature" in req.options:
                payload["temperature"] = req.options["temperature"]
            if "top_p" in req.options:
                payload["top_p"] = req.options["top_p"]
        payload["model"] = model
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
        # A model named by the CALLER wins; AZURE_MODEL is only the default.
        # It used to be `AZURE_MODEL or req.model`, so the global model always
        # won and no consumer could pick its own -- which is what made a cheap
        # model for news and a strong one for the agents impossible.
        # NOTE: embeddings() deliberately keeps the old behaviour; its model is
        # a separate deployment and a chat model name there breaks the embedder.
        model = _caller_model(req.model) or AZURE_MODEL
        payload: Dict[str, Any] = {
            "messages": [m.dict() for m in req.messages],
            "max_tokens": 2048,
        }
        if req.options:
            if "temperature" in req.options:
                payload["temperature"] = req.options["temperature"]
            if "top_p" in req.options:
                payload["top_p"] = req.options["top_p"]
        payload["model"] = model
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

# Effective 429 backoff, for the Settings > LLM Tuning panel.
#
# Reported by the PROCESS, not read from .env on disk, because those differ the
# moment someone edits .env without recreating the container — and a panel that
# shows the file rather than the running value would confirm a setting that is
# not actually in force.
@app.get("/config/backoff")
def backoff_config():
    return {
        "service": "llm_query",
        "mechanism": "retry-on-429 at the shared HTTP chokepoint "
                     "(news, scan-recommender, and anything else routed here)",
        "adaptive": False,
        "honours_retry_after": True,
        "env": {
            "LLM_429_MAX_RETRIES": LLM_429_MAX_RETRIES,
            "LLM_429_BASE_WAIT": LLM_429_BASE_WAIT,
            "LLM_429_MAX_WAIT": LLM_429_MAX_WAIT,
        },
    }


# Root-level kube-style health

@app.get("/healthz", response_model=HealthResponse)


def root_health():
    return health()

# Mount router

app.include_router(router)

# Native Ollama API paths (/api/*) so llm_query is a DROP-IN Ollama replacement:
# a client that points its Ollama base at http://llm_query:8002 gets its
# /api/generate, /api/tags, /api/chat, /api/embeddings translated to the
# configured backend (ollama/openai/azure). This lets the rag-api agents run on
# the selected backend (e.g. DeepSeek) instead of hitting Ollama directly.
api_router = APIRouter(prefix="/api")

def _proxy_version():
    return {"version": f"llm_query-proxy-{LLM_BACKEND}"}

api_router.add_api_route("/version", _proxy_version, methods=["GET"])
api_router.add_api_route("/tags", tags, methods=["GET"])
api_router.add_api_route("/ps", ps, methods=["GET"])
api_router.add_api_route("/generate", generate, methods=["POST"])
api_router.add_api_route("/chat", chat, methods=["POST"])
api_router.add_api_route("/embeddings", embeddings, methods=["POST"])
api_router.add_api_route("/embed", embeddings, methods=["POST"])
app.include_router(api_router)

# ---------- Local dev ----------
if __name__ == "__main__":
    # Run: OLLAMA_URL=http://localhost:11434 uvicorn llm_query:app --host 0.0.0.0 --port 8000
    import uvicorn
    uvicorn.run("llm_query:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), reload=False)
