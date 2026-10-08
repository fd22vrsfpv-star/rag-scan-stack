"""LiteLLM Router factory — PR 1 of the LiteLLM migration.

Why this module exists
----------------------
`llm_query/llm_query.py` is 1 400+ lines of hand-rolled provider adapters
(Azure OpenAI, Azure Foundry Anthropic, OpenAI direct, Anthropic native,
Ollama) with hand-rolled 429 retry, fallback, usage normalisation, URL
builders, header builders. Every new provider is 50-200 lines of custom
code + a probe session.

LiteLLM is the de-facto open-source router. Its `Router` speaks 130+
providers behind one OpenAI-compatible API, already knows Azure Foundry
Anthropic / Bedrock / Vertex / Ollama / OpenAI / Anthropic native /
Groq / Together, supports streaming / fallbacks / num_retries / cost
tracking out of the box, and chases upstream shape changes on their
release cadence.

This file is **step 1 of the swap**: it builds a `litellm.Router` from
the SAME `common.llm_settings.get_providers()` / `get_llm_settings()`
config layer the hand-rolled dispatch reads, so operators keep editing
providers through `Settings → LLM` and the router stays in sync. It
does NOT replace the dispatch yet — the handlers in `llm_query.py` are
untouched. PR 2 is where `_generate_text` starts calling
`router.completion()` and the hand-rolled provider helpers get deleted.

Keeping this parallel means PR 1 can land, be deployed and probed in
isolation, before any caller changes behaviour. If the router can't be
built on a given operator's config (bad api_key, missing endpoint,
unsupported provider type), PR 1 is a no-op — the hand-rolled path
keeps serving every call.

The three provider → model-name shapes we need to translate
-----------------------------------------------------------
`common.llm_settings.get_providers()` returns dicts of
`{id, type, endpoint, api_key, api_version, default_model, enabled, implicit}`
for every enabled provider. LiteLLM identifies providers by the model
string's PREFIX:

| provider type               | LiteLLM model string                 |
|-----------------------------|--------------------------------------|
| azure (openai deployment)   | `azure/<deployment>`                 |
| azure (foundry anthropic)   | `azure_ai/anthropic/<deployment>`    |
| anthropic (native)          | `anthropic/<model>`                  |
| ollama                      | `ollama/<model>` + `api_base`        |
| openai                      | `openai/<model>` (+ `api_base`)      |
| vllm                        | `openai/<model>` + `api_base`        |

The Azure Foundry Anthropic shape is the one the Foundry adapter work
discovered empirically: Azure OpenAI deployments live at
`<endpoint>/openai/v1/chat/completions`, Foundry Anthropic deployments
live at `<endpoint>/openai/v1/messages` and want the model string
prefixed `azure_ai/anthropic/`. The deployment name starting with
`claude-` is the signal LiteLLM uses to pick the Anthropic path.

Caller-override semantics
-------------------------
Today an explicit `model="prov_id:model_name"` in the request body
bypasses `llm.route.<task>` entirely. The router keeps that: the
`model_name` alias we register is exactly `prov_id:model_name`, so
`router.completion(model="prov_id:model_name", ...)` resolves 1:1 to
the right provider. A one-shot explicit model that is NOT in the
registered aliases falls through to the hand-rolled path (PR 2 adds a
one-off provider-prefix fallback for that case).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Sequence

try:
    from common.llm_settings import get_llm_settings, get_providers, get_route, LLM_TASK_NAMES
except Exception as e:  # pragma: no cover - common is always bind-mounted in prod
    logging.warning("litellm_router: common.llm_settings unimportable (%s) — "
                    "router will build only from caller-supplied settings", e)
    get_llm_settings = None
    get_providers = None
    get_route = None
    LLM_TASK_NAMES: Sequence[str] = ()

try:
    from litellm import Router  # type: ignore
except Exception as e:  # pragma: no cover - fails fast in the image if dep missing
    Router = None
    logging.warning("litellm_router: litellm not importable (%s) — "
                    "build_router_from_settings() will return None", e)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_router_from_settings(settings: Optional[Dict[str, Any]] = None,
                               *,
                               num_retries: int = 1,
                               timeout: float = 120.0):
    """Return a LiteLLM `Router` built from the active provider config.

    Returns `None` when litellm isn't installed OR the settings resolver
    isn't importable OR no enabled providers exist — callers fall back
    to the hand-rolled dispatch path in those cases. Never raises for
    an operator-config issue (an unknown provider type logs a WARNING
    and is skipped); only an actual LiteLLM constructor error
    propagates, because that is a bug worth fixing, not a config typo.
    """
    if Router is None or get_providers is None:
        return None
    settings = settings or (get_llm_settings() if get_llm_settings else {})
    model_list = _build_model_list(settings)
    if not model_list:
        return None
    fallbacks = _build_fallbacks(settings)
    return Router(model_list=model_list, fallbacks=fallbacks,
                  num_retries=num_retries, timeout=timeout)


def _build_model_list(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Turn each enabled provider's `default_model` into a LiteLLM
    `model_list` entry keyed by `<provider_id>:<model>`.

    The alias shape MATCHES what callers pass today in the `model`
    field (e.g. `azure-main:gpt-5-mini`, `ollama:qwen2.5:14b`), so a
    `router.completion(model=caller_model, ...)` call resolves without
    any translation layer in `llm_query.py`.
    """
    if get_providers is None:
        return []
    out: List[Dict[str, Any]] = []
    for p in get_providers(settings) or []:
        if not p.get("enabled"):
            continue
        entry = entry_for_provider(p)
        if entry is not None:
            out.append(entry)
    return out


def entry_for_provider(p: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Translate ONE provider dict into a LiteLLM `model_list` entry.

    Exposed (not `_entry_for_provider`) so `tests/test_litellm_router.py`
    can exercise each provider type in isolation — the test is the
    agreement contract between the DB-backed provider shape and
    LiteLLM's expected input.

    Returns `None` for a provider without a default_model (nothing to
    register), or one whose type we don't know how to translate yet
    (an unknown type is logged, not crashed — the hand-rolled dispatch
    still handles it).
    """
    pid = (p.get("id") or "").strip()
    ptype = (p.get("type") or "").strip().lower()
    model = (p.get("default_model") or "").strip()
    if not pid or not ptype:
        return None
    if not model:
        # An ollama provider with no default_model is still valid for
        # explicit-model callers (e.g. router.completion("ollama:qwen2.5:14b")),
        # but LiteLLM needs ONE entry per alias and we can't build an alias
        # without the model component. Skip for now — PR 2 adds a wildcard
        # path for one-shot explicit models not in the alias table.
        return None
    params: Dict[str, Any] = {}
    alias = f"{pid}:{model}"
    if ptype == "azure":
        # Three cases:
        #   (a) Foundry Anthropic (`claude-*` on *.services.ai.azure.com):
        #       model=`azure_ai/anthropic/<deployment>` AND
        #       api_base=`<root>/anthropic` (not just <root>). The
        #       `/anthropic` suffix is REQUIRED — LiteLLM 1.104's
        #       `azure_ai/anthropic/` provider resolves the model as
        #       the last segment and appends `/v1/messages` to the
        #       api_base. Without the suffix Azure gets a request for
        #       deployment literally named "anthropic/<model>" and
        #       returns DeploymentNotFound.
        #   (b) Foundry OpenAI (anything else on *.services.ai.azure.com):
        #       `azure_ai/<deployment>` — OpenAI-compat chat completions.
        #       This is where gpt-5-mini / o1-mini / o3-mini live, and
        #       `azure/<deployment>` would hit the classic Azure OpenAI
        #       REST path which Foundry rejects.
        #   (c) Classic Azure OpenAI (…/.openai.azure.com):
        #       `azure/<deployment>` — the historical path.
        ep = (p.get("endpoint") or "")
        is_foundry = _azure_endpoint_is_foundry(ep)
        if is_foundry:
            api_base = _strip_foundry_project_suffix(ep)
            if model.lower().startswith("claude-"):
                params["model"] = f"azure_ai/anthropic/{model}"
                # /anthropic suffix is REQUIRED for Foundry Anthropic
                # — see docstring above.
                if not api_base.rstrip("/").endswith("/anthropic"):
                    api_base = api_base.rstrip("/") + "/anthropic"
            else:
                params["model"] = f"azure_ai/{model}"
        else:
            api_base = ep
            params["model"] = f"azure/{model}"
        if api_base:
            params["api_base"] = api_base
        if p.get("api_key"):
            params["api_key"] = p["api_key"]
        params["api_version"] = p.get("api_version") or _AZURE_API_VERSION_DEFAULT
    elif ptype == "ollama":
        params["model"] = f"ollama/{model}"
        if p.get("endpoint"):
            params["api_base"] = p["endpoint"]
    elif ptype == "anthropic":
        params["model"] = f"anthropic/{model}"
        if p.get("api_key"):
            params["api_key"] = p["api_key"]
    elif ptype == "openai":
        params["model"] = f"openai/{model}"
        if p.get("endpoint"):
            params["api_base"] = p["endpoint"]
        if p.get("api_key"):
            params["api_key"] = p["api_key"]
    elif ptype == "vllm":
        # vLLM speaks the OpenAI chat-completions API; LiteLLM routes it
        # as `openai/<model>` with an api_base override. Same contract
        # llm_query's vllm branch uses today.
        params["model"] = f"openai/{model}"
        if p.get("endpoint"):
            params["api_base"] = p["endpoint"]
    else:
        logging.warning("litellm_router: unknown provider type %r (id=%r) — "
                        "skipping, hand-rolled dispatch still serves it", ptype, pid)
        return None
    return {"model_name": alias, "litellm_params": params}


def _build_fallbacks(settings: Dict[str, Any]) -> List[Dict[str, List[str]]]:
    """Turn each per-task `fallbacks` entry into LiteLLM's
    `fallbacks=[{primary_alias: [backup_alias, ...]}]` shape.

    `get_route(task)` is the ONLY correct way to resolve a task → alias
    today: it already walks route → agent_models → route.default and
    then `_resolve_one()` parses the raw string against the configured
    providers. Reusing it keeps the router aware of exactly the same
    overrides the hand-rolled dispatcher honours.
    """
    if get_route is None:
        return []
    out: List[Dict[str, List[str]]] = []
    for task in LLM_TASK_NAMES:
        try:
            r = get_route(task, settings)
        except Exception as e:  # noqa: BLE001
            logging.warning("litellm_router: get_route(%r) failed (%s) — no fallback registered", task, e)
            continue
        if not r or not r.get("fallback"):
            continue
        prim_alias = f"{r.get('provider')}:{r.get('model')}"
        fb = r["fallback"]
        fb_alias = f"{fb.get('provider')}:{fb.get('model')}"
        if prim_alias == fb_alias:
            # _resolve_one dedupes already, but belt-and-braces: a
            # self-fallback would be a 429 → 429 round-trip, not a recovery.
            continue
        out.append({prim_alias: [fb_alias]})
    return out


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
# `common.llm_settings.get_llm_settings()` already has a 30-second cache; the
# router is cheap to rebuild on top of that cache (no network calls), but we
# memoise one anyway so the common case (every request on a stable config) is
# a dict lookup. Operator saves in the Settings UI invalidate implicitly via
# the settings cache TTL — same semantics as the hand-rolled dispatch.
_router_cache: Dict[str, Any] = {"router": None, "config_fingerprint": None}


def _config_fingerprint(settings: Dict[str, Any]) -> str:
    """A fingerprint of just the fields the router depends on.

    Using the FULL settings dict as a cache key would mis-hit on changes
    that don't actually affect the router (e.g. UI-only toggles). Fingerprint
    is `providers | routes | fallbacks` serialised; a settings reload where
    none of those three changed is a cache hit.
    """
    import hashlib
    import json
    payload = {
        "providers": settings.get("providers") if settings else None,
        "routes": settings.get("routes") if settings else None,
        "fallbacks": settings.get("fallbacks") if settings else None,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def get_router():
    """Cached router — rebuilt only when the fingerprint of the
    routing-relevant settings changes."""
    settings = get_llm_settings() if get_llm_settings else {}
    fp = _config_fingerprint(settings)
    if _router_cache["router"] is not None and _router_cache["config_fingerprint"] == fp:
        return _router_cache["router"]
    router = build_router_from_settings(settings)
    _router_cache["router"] = router
    _router_cache["config_fingerprint"] = fp
    return router


def router_available() -> bool:
    """True if the router can be built right now (dependency installed +
    settings importable + at least one enabled provider). PR 2 uses this
    as the gate on routing through LiteLLM vs falling back to the hand-
    rolled path."""
    try:
        return get_router() is not None
    except Exception as e:  # noqa: BLE001
        logging.debug("litellm_router: router_available() failed: %s", e)
        return False


# Kill switch — operator-facing toggle so the LiteLLM path can be disabled
# WITHOUT a rebuild if a provider shape LiteLLM gets wrong turns up in
# production. `_generate_text` reads this before taking the router path.
#
# Default DIFFERS by PR:
#   PR 1 — default OFF (nothing wired in yet)
#   PR 2 — default ON (the swap is in; hand-rolled is the fallback path)
#   PR 3 — default ON, env override still honoured
#   PR 4 — default ON, env override removed once smoke tests pass
LITELLM_ROUTER_ENABLED = os.environ.get("LITELLM_ROUTER_ENABLED", "true").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# One-shot completion (PR 2 wiring)
# ---------------------------------------------------------------------------
# `_generate_text` in llm_query.py receives explicit (backend, model, endpoint,
# api_key) per call — not an alias. This helper translates that shape into a
# `litellm.completion(...)` call with the right provider prefix + credentials
# and returns the (text, usage) tuple matching `_usage_from()`'s contract.
#
# The Router from `build_router_from_settings` is still built (used for
# `router_available()` + fallback-alias registration) but PR 2's dispatch
# goes through `litellm.completion` directly, because the caller already
# knows which provider instance it wants. That matches the hand-rolled
# dispatcher's semantics 1:1 — explicit (backend, model) wins.


# api_version default picks a release that supports gpt-5 / o1 / o3
# reasoning deployments (which rejected older versions with
# "API version not supported"). The hand-rolled dispatcher pins
# 2024-08-01-preview via AZURE_API_VERSION; 2024-10-21 is the first
# GA version that supports max_completion_tokens + reasoning deploys.
# A provider-row api_version wins when set.
_AZURE_API_VERSION_DEFAULT = "2024-10-21"


def _azure_endpoint_is_foundry(endpoint: str) -> bool:
    """True for a Microsoft Azure Foundry endpoint (Azure AI Services) —
    same signal `_azure_is_foundry` uses in the hand-rolled dispatcher.
    Foundry serves ALL deployments (OpenAI + Anthropic + others) through
    the OpenAI-compat `/openai/v1/chat/completions` path, which LiteLLM
    reaches via the `azure_ai/<deployment>` prefix. The classic Azure
    OpenAI resource endpoint (…/.openai.azure.com) uses the `azure/`
    prefix instead."""
    b = (endpoint or "").lower()
    return (".services.ai.azure.com" in b or "/openai/v1" in b
            or b.rstrip("/").endswith("/openai"))


def _strip_foundry_project_suffix(endpoint: str) -> str:
    """Foundry PROJECT endpoints look like
    `https://<resource>.services.ai.azure.com/api/projects/<name>`.
    LiteLLM wants the RESOURCE root as `api_base`, so strip the
    `/api/projects/<name>` suffix — same thing `_azure_foundry_root`
    does for the hand-rolled dispatch. Idempotent: a resource-root
    endpoint comes back unchanged."""
    import re
    b = (endpoint or "").rstrip("/")
    b = re.sub(r"/api/projects/[^/]+/?$", "", b, flags=re.I)
    return b.rstrip("/")


def litellm_completion_for(backend: str,
                           model: str,
                           prompt: str,
                           options: Optional[Dict[str, Any]],
                           endpoint: Optional[str] = None,
                           api_key: Optional[str] = None,
                           max_tokens: int = 8192,
                           api_version: Optional[str] = None):
    """Dispatch one prompt through LiteLLM.

    Returns `(text, usage)` where `usage` is the same
    `{prompt_tokens, completion_tokens, total_tokens}` shape
    `_usage_from()` emits — so `_generate_text` can swap in this call
    without any downstream reshape.

    Returns `None` for an unknown backend (caller falls back to the
    hand-rolled dispatch — same contract as `entry_for_provider`).
    Raises on provider errors so the caller can decide between
    propagate-vs-fallback.
    """
    import litellm  # local import — the module is heavy, don't pay import cost unused
    lmodel, kwargs = _build_litellm_kwargs(
        backend, model, options, endpoint, api_key, max_tokens, api_version)
    if lmodel is None:
        return None
    # Single-prompt → wrap as one user message. For multi-turn, use
    # `litellm_chat_completion_for()` which takes messages directly.
    kwargs["messages"] = [{"role": "user", "content": prompt}]
    resp = _litellm_completion_with_azure_shape_retry(litellm, backend, model, lmodel, kwargs)
    return _extract_text_and_usage(resp)


def _build_litellm_kwargs(backend: str,
                          model: str,
                          options: Optional[Dict[str, Any]],
                          endpoint: Optional[str],
                          api_key: Optional[str],
                          max_tokens: int,
                          api_version: Optional[str]) -> tuple:
    """Shared backend→(model_string, kwargs) picker used by both the
    single-prompt and multi-turn LiteLLM wrappers. Returns
    `(None, {})` for an unknown backend — the caller falls back to the
    hand-rolled dispatch, same contract as `entry_for_provider`.

    `kwargs` is returned WITHOUT `messages` so the caller can set its
    own (single-prompt or multi-turn shape).
    """
    temp = (options or {}).get("temperature")
    top_p = (options or {}).get("top_p")
    kwargs: Dict[str, Any] = {"max_tokens": max_tokens}
    if temp is not None:
        kwargs["temperature"] = temp
    if top_p is not None:
        kwargs["top_p"] = top_p
    b = (backend or "").lower()
    if b == "azure":
        # Mirrors entry_for_provider()'s three-case Azure handling:
        # (a) Foundry Anthropic → azure_ai/anthropic/<model>
        #     + api_base = <root>/anthropic (REQUIRED suffix — see
        #     entry_for_provider docstring)
        # (b) Foundry OpenAI    → azure_ai/<model>   (gpt-5 / o1 / o3 land here)
        # (c) Classic Azure OAI → azure/<model>
        is_foundry = _azure_endpoint_is_foundry(endpoint or "")
        if is_foundry:
            api_base = _strip_foundry_project_suffix(endpoint or "")
            if (model or "").lower().startswith("claude-"):
                lmodel = f"azure_ai/anthropic/{model}"
                if not api_base.rstrip("/").endswith("/anthropic"):
                    api_base = api_base.rstrip("/") + "/anthropic"
            else:
                lmodel = f"azure_ai/{model}"
        else:
            api_base = endpoint or ""
            lmodel = f"azure/{model}"
        if api_base:
            kwargs["api_base"] = api_base
        if api_key:
            kwargs["api_key"] = api_key
        kwargs["api_version"] = api_version or _AZURE_API_VERSION_DEFAULT
    elif b == "openai":
        lmodel = f"openai/{model}"
        if endpoint:
            kwargs["api_base"] = endpoint
        if api_key:
            kwargs["api_key"] = api_key
    elif b == "anthropic":
        lmodel = f"anthropic/{model}"
        if api_key:
            kwargs["api_key"] = api_key
    elif b == "ollama":
        lmodel = f"ollama/{model}"
        if endpoint:
            kwargs["api_base"] = endpoint
    elif b == "vllm":
        # vLLM speaks OpenAI chat completions. Same translation as the
        # hand-rolled vllm branch (base + /v1/chat/completions).
        lmodel = f"openai/{model}"
        if endpoint:
            kwargs["api_base"] = endpoint
    else:
        return (None, {})
    return (lmodel, kwargs)


def litellm_chat_completion_for(backend: str,
                                model: str,
                                messages: list,
                                options: Optional[Dict[str, Any]],
                                endpoint: Optional[str] = None,
                                api_key: Optional[str] = None,
                                max_tokens: int = 8192,
                                api_version: Optional[str] = None):
    """Multi-turn chat variant of `litellm_completion_for`.

    Takes the OpenAI-shape `messages` list directly (preserving system /
    user / assistant turn boundaries, which the single-prompt path would
    flatten). Same return contract: `(text, usage)` or `None` for an
    unknown backend. Used by `chat()` endpoint's non-routed branches
    after the LiteLLM cutover.

    Shares the backend → model-string translation table with
    `litellm_completion_for` so the two paths stay in sync. Any provider
    shape change applied to one must land in the other — the shape
    picker is extracted into `_build_litellm_kwargs()` below.
    """
    import litellm
    lmodel, kwargs = _build_litellm_kwargs(
        backend, model, options, endpoint, api_key, max_tokens, api_version)
    if lmodel is None:
        return None
    # Chat takes `messages` instead of a wrapped single-user prompt.
    kwargs["messages"] = messages
    resp = _litellm_completion_with_azure_shape_retry(litellm, backend, model, lmodel, kwargs)
    return _extract_text_and_usage(resp)


def _litellm_completion_with_azure_shape_retry(litellm_mod, backend: str,
                                               model: str, lmodel: str,
                                               kwargs: Dict[str, Any]):
    """Call `litellm.completion(model=lmodel, **kwargs)` with a bounded
    retry for Azure Foundry resources that host OpenAI-compat deployments.

    Azure's `.services.ai.azure.com` hostname is used for BOTH:
      (A) Foundry Models-as-a-Service (DeepSeek, Mistral, Phi, Llama,
          Anthropic) served by Microsoft — LiteLLM reaches these via
          `azure_ai/[<prefix>/]<model>`.
      (B) The operator's own OpenAI-compat deployment hosted on that
          resource — reachable at `<endpoint>/openai/v1/chat/completions`
          with the model name in the request body (not the URL path).

    The hostname alone doesn't tell them apart. We default to (A) in
    `_build_litellm_kwargs()`, then on a NotFoundError here retry
    as (B) — `openai/<model>` with `api_base=<endpoint>/openai/v1`.
    If both fail the second exception propagates with context so the
    operator sees "both shapes 404'd" rather than one or the other.

    Memoises the successful shape per (endpoint, model) so subsequent
    calls skip the first attempt. Classic Azure OpenAI endpoints
    (…/.openai.azure.com) + Foundry Anthropic (claude-* deployment names)
    never enter the retry — their shapes are unambiguous.
    """
    is_azure = (backend or "").lower() == "azure"
    is_foundry_openai = (is_azure and lmodel.startswith("azure_ai/")
                         and not lmodel.startswith("azure_ai/anthropic/"))
    endpoint = kwargs.get("api_base") or ""
    cache_key = (endpoint, model)
    pinned = _AZURE_SHAPE_CACHE.get(cache_key) if is_foundry_openai else None
    if pinned == "openai_compat":
        return _call_litellm_openai_compat(litellm_mod, model, kwargs)
    try:
        return litellm_mod.completion(model=lmodel, **kwargs)
    except Exception as e:  # noqa: BLE001
        # Narrow retry: only for Azure Foundry OpenAI-compat 404 on the
        # azure_ai shape. Anything else raises as-is so a real error
        # (bad credentials, provider down) doesn't get retried blindly.
        if not is_foundry_openai:
            raise
        msg = str(e).lower()
        if "404" not in msg and "not found" not in msg and "notfound" not in msg:
            raise
        logging.info("litellm_router: azure_ai/ 404 for %r on %s — retrying with openai-compat shape",
                     model, endpoint)
        try:
            resp = _call_litellm_openai_compat(litellm_mod, model, kwargs)
            _AZURE_SHAPE_CACHE[cache_key] = "openai_compat"
            logging.info("litellm_router: pinned (%s, %s) to openai_compat shape", endpoint, model)
            return resp
        except Exception as e2:  # noqa: BLE001
            # Surface BOTH failures so the operator sees what each shape
            # returned — the hand-rolled fallback that catches this
            # exception will still save the call, but the pin tells them
            # neither LiteLLM shape handles this provider yet.
            raise RuntimeError(
                f"both LiteLLM shapes failed for {model} on {endpoint}: "
                f"azure_ai/ said {e}; openai-compat said {e2}") from e2


def _call_litellm_openai_compat(litellm_mod, model: str,
                                base_kwargs: Dict[str, Any]):
    """Second-chance shape: route an Azure Foundry OpenAI-compat deployment
    through LiteLLM's `openai/` provider. The Foundry resource serves
    `/openai/v1/chat/completions` with the model name in the request body,
    which is exactly what LiteLLM's openai provider sends when `api_base`
    is pointed at that path.
    """
    kw = dict(base_kwargs)
    # api_base: swap the azure path for the openai-compat path.
    api_base = kw.get("api_base", "").rstrip("/")
    if not api_base.endswith("/openai/v1"):
        kw["api_base"] = api_base.rstrip("/") + "/openai/v1"
    # api_version is an Azure-only param; LiteLLM's openai provider rejects it.
    kw.pop("api_version", None)
    return litellm_mod.completion(model=f"openai/{model}", **kw)


_AZURE_SHAPE_CACHE: Dict[tuple, str] = {}


def _extract_text_and_usage(resp) -> tuple:
    """Pull `(text, usage_dict)` out of a `litellm.ModelResponse` in the
    same normalised shape `_usage_from` emits. Factored out so the
    single-prompt and multi-turn LiteLLM wrappers return identically-
    shaped tuples.
    """
    text = resp.choices[0].message.content if getattr(resp, "choices", None) else ""
    usage_out: Dict[str, Any] = {}
    u = getattr(resp, "usage", None)
    if u is not None:
        pt = getattr(u, "prompt_tokens", None)
        ct = getattr(u, "completion_tokens", None)
        tt = getattr(u, "total_tokens", None)
        if pt is not None:
            usage_out["prompt_tokens"] = int(pt)
        if ct is not None:
            usage_out["completion_tokens"] = int(ct)
        if tt is not None:
            usage_out["total_tokens"] = int(tt)
    # Cost — LiteLLM 1.57+ attaches a USD amount to `response._hidden_params`
    # (`response_cost`), computed from its built-in price catalog. Grab it
    # here so the per-call insert into `llm_request_metrics` has a real
    # dollar figure to persist. The catalog covers every provider LiteLLM
    # knows (Azure OpenAI, Foundry Anthropic, OpenAI direct, Anthropic
    # native, Bedrock, Vertex, Groq, Together, Ollama = 0.0). An unknown
    # model falls through to `None` → the schema stores NULL, which the
    # UI renders as "—".
    try:
        hp = getattr(resp, "_hidden_params", None) or {}
        cost = hp.get("response_cost") if isinstance(hp, dict) else None
        if cost is None:
            # Fallback for older LiteLLM lines or custom models not in the
            # price catalog: compute from cost_calculator if importable.
            try:
                from litellm import completion_cost
                cost = completion_cost(completion_response=resp)
            except Exception:  # noqa: BLE001
                cost = None
        if cost is not None:
            # Round at 6 decimal places — the price catalog's smallest unit
            # is ~$0.000001/token for cheap models; 6 d.p. preserves it
            # without noise.
            usage_out["cost_usd"] = round(float(cost), 6)
    except Exception as e:  # noqa: BLE001
        logging.debug("litellm_router: cost extraction failed (%s)", e)
    return text, usage_out
