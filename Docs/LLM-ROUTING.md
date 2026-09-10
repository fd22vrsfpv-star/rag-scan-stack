# LLM providers, per-task routing, and rate-limit fallback

Configure several LLM backends at once, choose which model each task uses, and
name a fallback for when a provider rate-limits you.

Everything here is set in **Settings → LLM Tuning** and stored in the
`app_settings` table, so it takes effect without editing `.env` or recreating a
container. Resolution is shared by every service through
`common/llm_settings.py`, and caches for **30 seconds** — a change is not
instant everywhere.

---

## Why

One model for the whole stack is wrong in both directions: a frontier model is
wasted summarising security news, and a cheap model fumbles tool calls in the
exploit phase. Separately, a single provider's per-deployment token-per-minute
quota is easy to exhaust, and when it is, the useful response is to use a
different model rather than fail.

---

## 1. Providers

A **provider** is a named backend instance. Naming them is what allows *two
configs of the same type* — two Azure resources, say — to be usable at once.

| Field | Notes |
|---|---|
| `id` | Operator-chosen, e.g. `azure-main`. **May not contain `:`** (routes split on it). |
| `type` | `azure` \| `openai` \| `anthropic` \| `ollama` \| `vllm` |
| `endpoint` | The **bare resource URL**. See *Endpoint shapes* below. |
| `api_key` | Stored server-side; the API returns it masked and a masked value on save keeps the stored key. |
| `default_model` | Used when a route names the provider but no model (`azure-main:`). |
| `enabled` | Unchecked providers are ignored entirely. |

Stored as a JSON array in `llm.providers`.

**The single-backend fields still work.** Each backend type also appears as an
*implicit* provider named after its type (`azure`, `ollama`, …), built from the
existing `llm.azure_*` / `llm.ollama_*` keys. So a deployment that has never
touched this page keeps working, and a route naming a type (`azure:some-model`)
is still valid. An explicit provider whose id collides with a type name wins.

### Endpoint shapes

For Azure, paste the **bare resource URL** — `https://<res>.services.ai.azure.com/`.
These are all normalised to the same root, because they are all things the
portal will hand you:

    https://res.services.ai.azure.com/
    https://res.services.ai.azure.com/openai
    https://res.services.ai.azure.com/openai/v1
    https://res.services.ai.azure.com/openai/v1/chat/completions
    https://res.services.ai.azure.com/openai/v1/responses      <- Responses API URL
    https://res.services.ai.azure.com/api/projects/<name>      <- Foundry project

Note the stack speaks **chat completions**, not the Responses API. The
`/responses` URL is accepted and normalised, but nothing calls that endpoint.

### The Test button

Each provider row has one. It reports four stages separately, because they look
identical from outside and mean entirely different things:

| Stage | Distinguishes |
|---|---|
| `endpoint` | a URL shape that cannot be built from |
| `auth` | key rejected vs host unreachable |
| `deployments` | **a resource that authenticates fine and serves nothing** |
| `generate` | the only proof of usability — a 404 here means the default model is not on *this* resource |

It uses the stored key, never one typed into the browser.

---

## 2. Per-task routes

`llm.route.<task>` names the model for a task. Tasks:

| Task | Used by |
|---|---|
| `recon` | Reconnaissance agent |
| `analyze` | Analyzer agent (also the Report phase) |
| `exploit` | Exploit agent |
| `scan` | Scanner agent |
| `postex` | Post-exploitation review |
| `news` | Security-news enrichment (high volume, low difficulty) |
| `recommend` | Scan recommender |
| `exploit_gen` | Exploit/PoC script generation |
| `extract` | Extractor learning |
| `triage` | Cloud/artifact triage |
| `chat` | Operator chat |

Value forms:

| Value | Meaning |
|---|---|
| `claude-sonnet-5` | that model on the current backend |
| `azure-main:gpt-5-mini` | that model on that **named provider** |
| `azure:claude-sonnet-5` | that model on the implicit provider for the type |
| `local:` | that provider, with its configured `default_model` |
| *(empty)* | inherit `llm.route.default`, else the global model |

**Only the first colon splits**, and only when the prefix names a known backend
or provider id — otherwise an Ollama tag like `qwen2.5:14b` would parse as a
provider called `qwen2.5`.

**A task with no route behaves exactly as before routing existed.** That is
what makes this safe to enable on an existing install.

Agents map to tasks by name (`Reconnaissance` → `recon`, `Analyzer` →
`analyze`, `Exploit` → `exploit`, …). For the agent phases the routed **model**
is substituted; the backend is not switched, because each backend needs its own
LangChain client and those agents depend on reliable tool calling.

### Model dropdowns list deployed models only

For Azure, `/openai/v1/models` returns the **regional catalog** — hundreds of
entries, of which only the deployed ones answer; the rest return
`DeploymentNotFound`. Deployments are read from

    GET {endpoint}/openai/deployments?api-version=2023-03-15-preview

(that api-version specifically — `2024-08-01-preview` returns 404), filtered to
`status = succeeded`. For Ollama the list comes from `/api/tags`, which is the
real installed list. The catalog size is shown as text only, never as options.
A `Custom…` option is always available for anything not discovered.

---

## 3. Rate-limit fallback

`llm.route.<task>.fallback`, or `llm.route.default.fallback` for all tasks.
Same value forms as a route.

The fallback is used **only** when the primary returns 429 *after* the retry
layer has already waited out the provider's `Retry-After`
(`LLM_429_MAX_RETRIES` / `_BASE_WAIT` / `_MAX_WAIT` on `llm_query`). At that
point the quota is genuinely gone and waiting longer will not help — a
different model is the only thing that will.

Rules worth knowing:

- **429 only.** A 400 or 404 is a configuration error, and answering it from
  another model would hide the mistake. Those are re-raised naming the provider
  and task: `provider 'azure-gpt5' (task 'extract'): DeploymentNotFound`.
- **A fallback identical to the primary is dropped** — it would just 429 twice.
  Compared on *(provider, model)*, so the same model on a different provider
  instance **is** a valid fallback: separate deployment, separate quota.
- **No fallback configured means the 429 propagates.** Silently answering from
  a model the operator never chose is worse than a visible failure.
- A failover is reported in the response (`failed_over: true`, plus the
  `provider` that answered), because a silent model substitution is invisible.

The pentest agents have their own governor (`LLM_RATELIMIT_*`, adaptive AIMD in
`autogen_agents/langgraph_engine.py`) because they call the provider directly
through LangChain rather than through `llm_query`.

---

## Running a task on a local Ollama

Keeps that task's data on the host and off a paid quota entirely:

1. Run Ollama on the host and pull a model.
2. Add a provider — `id: local`, `type: ollama`,
   `endpoint: http://host.docker.internal:11434`, `default_model: qwen2.5:14b`.
3. Press **Test**.
4. Set the task's route to `local:`.

`news` is the usual candidate: high volume, low difficulty.

---

## Data locality

Routing a task to a local provider keeps its prompt — findings, hostnames, tool
output — on the host. Routing it to Azure, OpenAI or Anthropic sends that
prompt to the provider. Nothing leaves the host unless a provider that is not
on the host is configured and routed to.

---

## Environment fallbacks

Useful for a fresh install before anything is set in the UI. DB settings always
win.

| Variable | Sets |
|---|---|
| `LLM_PROVIDERS` | the providers JSON array |
| `LLM_ROUTE_<TASK>` | one task's route |
| `LLM_ROUTE_<TASK>_FALLBACK` | one task's fallback |
| `LLM_ROUTE_FALLBACK` | the global fallback |
| `LLM_429_MAX_RETRIES` / `_BASE_WAIT` / `_MAX_WAIT` | llm_query's 429 retry |
| `LLM_RATELIMIT_*` | the agents' own governor |
| `NEWS_LLM_MODEL` / `NEWS_LLM_URL` | pin news enrichment directly |

## Troubleshooting

| Symptom | Cause |
|---|---|
| A change did not take effect | 30s resolver cache. Wait, then re-check. |
| `DeploymentNotFound` | the model is not deployed on *that* provider's resource. Press **Test**: `deployments` shows what is. |
| `400 unsupported_parameter … max_completion_tokens` | handled automatically — `llm_query` retries with the right parameter for gpt-5 / o-series models. |
| A provider tests `auth OK` but `deployments NONE` | the resource is real and the key works, but nothing is deployed on it. |
| `502 … unreachable` | endpoint wrong or the service is not running. |
| Everything ignores a route | check `llm_query` can import the resolver: `scripts/post-install-check.sh` asserts this. |
