# Deferred TODO — swap hand-rolled `llm_query` for LiteLLM

**Status:** deferred, prioritized after the Foundry Anthropic adapter
is in prod.
**Written:** 2026-10-05 (right after shipping the Anthropic-on-Foundry
adapter).

## Why

We just spent ~2 hours probing Azure AI Foundry's Anthropic passthrough,
discovering empirically which URL / auth / api-version / model-id shape
works, and shipping a bespoke adapter for exactly one provider surface.
Every new provider (Vertex, Bedrock Anthropic, Groq, Together,
OpenRouter, Mistral, Cohere, ...) hits the same cycle, and the next time
Microsoft or Anthropic changes a header, we discover it in production.

**LiteLLM** is the de-facto open-source LLM router. It:
- Speaks 130+ providers behind one OpenAI-compat API
- Already knows Azure Foundry Anthropic, Bedrock, Vertex, Ollama,
  OpenAI, Anthropic native, Groq, Together, etc. — chases upstream
  shape changes on their release cadence, not ours
- Supports streaming, cost tracking, retries, rate-limit back-off,
  fallbacks, request caching, Pydantic structured output, token
  counting, caller observability — all today
- Config as YAML OR drop-in Python SDK OR proxy-server mode

Our hand-rolled `llm_query.py` reimplements a subset of this and keeps
growing (OpenAI chat, Azure chat, Anthropic native, Ollama, Foundry
Anthropic, usage normalization, 429 retry, per-caller route resolution).
Every added provider is 50-200 lines of custom code + a probe session.

## What stays, what goes

**Stays:**
- `common/llm_settings.py` — the DB-backed `app_settings` config layer
  is the operator surface and the single source of provider+route truth.
  LiteLLM is instantiated FROM this config at startup / on reload.
- `/healthz`, `/api/*` (ollama-compat), `/openai/*` endpoints — public
  surface that `rag-api` and the agents call. Keep every path and shape.
- Caller-override via explicit `model` field — same semantics (an
  explicit model wins over the DB route).
- Token-usage normalization + telemetry writes to `app_settings`-adjacent
  logs. LiteLLM returns a `usage` dict already; just rename keys.

**Goes:**
- `_generate_text` per-backend branches: LiteLLM dispatches.
- `_azure_json_post`, `_azure_chat_url`, `_azure_foundry_root`,
  `_azure_anthropic_messages_post`, `_foundry_anthropic_client`,
  `_openai_json_post`, `_anthropic_json_post` — all deleted.
- Hand-rolled 429 retry + fallback loop — LiteLLM has
  `fallbacks=[...]` + `num_retries=N` config.
- Per-provider endpoint URL builders — LiteLLM reads the provider from
  the `model` string prefix (`azure/`, `azure_ai/anthropic/`,
  `anthropic/`, `ollama/`, `openai/`, ...).

## Scope

**In:**
1. Add `litellm` to `llm_query` requirements + Dockerfile.
2. Build a `_litellm_router()` factory that:
   - Reads providers from `app_settings` via existing
     `get_llm_settings()`.
   - Translates each provider into LiteLLM's `model_list` entries,
     prefixing the model name correctly for the provider type:
     - `type: azure`  → `model: azure/<deployment>`
     - `type: azure`, deployment starts with `claude-` →
       `model: azure_ai/anthropic/<deployment>` (Foundry Anthropic)
     - `type: anthropic` → `model: anthropic/<model>`
     - `type: ollama`   → `model: ollama/<model>` + `api_base`
     - `type: openai`   → `model: openai/<model>`
   - Builds a LiteLLM `Router` with these entries + the current
     `llm.route.*` map as fallbacks.
3. Replace `_generate_text` body with a `router.completion(...)` call;
   keep the same (text, usage) return shape.
4. Delete every hand-rolled provider helper the router replaces.
5. Add 3 agreement tests that pin:
   - OpenAI chat path returns same text shape as before
   - Azure Foundry Anthropic returns same text shape as before
   - Ollama local returns same text shape as before
6. Document the new provider-list format in CLAUDE.md's LLM section.

**Out:**
- Changing anything about the operator-facing config UI
  (`Settings → LLM`). Config stays as-is; LiteLLM just reads it.
- Replacing the `/ollama/*` endpoint surface callers depend on.
- Replacing the embedder service — it's a separate concern.
- Replacing per-call telemetry writes — the router already emits usage.

## Design (sketch)

```python
# llm_query/llm_query.py (after)

from litellm import Router

_router_cache = {"router": None, "config_hash": None}

def _build_router_from_settings() -> Router:
    s = get_llm_settings()
    providers = get_providers(s)
    model_list = []
    for p in providers:
        if not p.get("enabled"): continue
        pid, ptype, model = p["id"], p["type"], p.get("default_model")
        entry = {"model_name": f"{pid}:{model}", "litellm_params": {}}
        if ptype == "azure":
            if (model or "").lower().startswith("claude-"):
                entry["litellm_params"]["model"] = f"azure_ai/anthropic/{model}"
            else:
                entry["litellm_params"]["model"] = f"azure/{model}"
            entry["litellm_params"]["api_base"] = p["endpoint"]
            entry["litellm_params"]["api_key"] = p["api_key"]
            entry["litellm_params"]["api_version"] = p.get("api_version") or "2024-05-01-preview"
        elif ptype == "ollama":
            entry["litellm_params"]["model"] = f"ollama/{model}"
            entry["litellm_params"]["api_base"] = p["endpoint"]
        elif ptype == "anthropic":
            entry["litellm_params"]["model"] = f"anthropic/{model}"
            entry["litellm_params"]["api_key"] = p["api_key"]
        elif ptype == "openai":
            entry["litellm_params"]["model"] = f"openai/{model}"
            entry["litellm_params"]["api_base"] = p.get("endpoint")
            entry["litellm_params"]["api_key"] = p["api_key"]
        model_list.append(entry)
    fallbacks = []
    for route_key in ("default", "extract", "exploit", "news"):
        prim = s.get(f"route.{route_key}")
        back = s.get(f"route.{route_key}.fallback")
        if prim and back:
            fallbacks.append({prim: [back]})
    return Router(model_list=model_list, fallbacks=fallbacks,
                  num_retries=1, timeout=REQUEST_TIMEOUT)
```

Delete: `_azure_json_post`, `_azure_chat_url`, `_azure_embed_url`,
`_azure_headers`, `_openai_json_post`, `_openai_chat_url`,
`_openai_headers`, `_anthropic_json_post`, `_anthropic_headers`,
`_anthropic_extract_text`, `_azure_anthropic_messages_post`,
`_foundry_anthropic_client`, `_is_anthropic_on_foundry`,
`_foundry_resource_root`, `_post_with_429_retry`, `_generate_routed`.
Approx 500 lines of custom provider code removed.

## Risks / tradeoffs

- **LiteLLM is actively developed** — breaking changes do happen. Pin
  a version (`litellm==1.56.x` or whatever is current when we migrate)
  and bump deliberately.
- **New dependency surface** — LiteLLM pulls in `tiktoken`, provider
  SDKs lazily. The llm_query image gets bigger. Mitigation: pin the
  lazy-loaded providers so we only install Azure + Anthropic + Ollama
  SDKs, not Vertex / Bedrock / Groq.
- **Caller-override semantics** — today a call with `model="xxx:yyy"`
  bypasses routing entirely. LiteLLM supports this via
  `router.completion(model="xxx:yyy", ...)` if the alias exists in
  `model_list`; needs a fallback path for one-shot explicit models not
  in the config.
- **Token-usage normalization** — LiteLLM returns `usage.prompt_tokens`
  et al for every provider (shape translation is in-router). We rename
  to our existing keys.

## Verification plan

After swap:
1. `/ollama/generate` with `model=qwen2.5:14b` → text matches current
   behaviour; usage dict carries `prompt_tokens` + `completion_tokens`.
2. `/ollama/generate` with `model=azure-main:gpt-5-mini` → routes to
   Azure OpenAI; same shape.
3. `/ollama/generate` with `model=sonnet-4-5:claude-sonnet-4-5` → routes
   to Foundry Anthropic (once the deployment is fixed); same shape.
4. 429 from a configured provider → LiteLLM retry + fallback consumes
   the fallback entry.
5. Agent sessions run end-to-end with no caller-side code change.

## Rollout order

1. PR 1 — add `litellm` dep + `_build_router_from_settings` + unit
   tests. No handler changes.
2. PR 2 — swap `_generate_text` to router.completion; delete half the
   provider helpers; keep OpenAI-compat endpoint surface identical.
3. PR 3 — delete remaining provider helpers; remove the Foundry
   Anthropic adapter files; update CLAUDE.md.
4. PR 4 — smoke-test all configured providers end-to-end against real
   endpoints; land only after a successful focused-10 CVE run proves
   the agent paths are intact.

## When to pick this back up

- After the current CVE-Bench focused-10 run completes on sonnet-4-5
  (the adapter needs to work end-to-end first, so we have a reference
  verdict to compare against).
- Before adding a THIRD custom provider (Vertex, Bedrock, Groq — any).
  The cost of this migration is paid back the moment we avoid one more
  hand-rolled provider.
