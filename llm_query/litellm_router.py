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
        # Foundry Anthropic deployments carry `claude-*` as their deployment
        # name — the signal LiteLLM uses to pick the azure_ai/anthropic path
        # over azure/openai. Same empirical rule the Foundry adapter uses
        # today (see _is_anthropic_on_foundry in llm_query.py).
        if model.lower().startswith("claude-"):
            params["model"] = f"azure_ai/anthropic/{model}"
        else:
            params["model"] = f"azure/{model}"
        if p.get("endpoint"):
            params["api_base"] = p["endpoint"]
        if p.get("api_key"):
            params["api_key"] = p["api_key"]
        params["api_version"] = p.get("api_version") or "2024-05-01-preview"
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


# Opt-in kill switch so the operator can disable the LiteLLM path WITHOUT
# a rebuild if PR 2's swap turns up a provider shape LiteLLM gets wrong.
# When PR 2 lands, `_generate_text` consults this before taking the router
# path — defaulting to `enabled` once we've completed PR 4's smoke tests.
LITELLM_ROUTER_ENABLED = os.environ.get("LITELLM_ROUTER_ENABLED", "false").lower() in ("1", "true", "yes")
