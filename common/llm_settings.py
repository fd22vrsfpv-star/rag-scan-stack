"""Resolve the effective LLM backend config: dashboard DB settings over .env.

The LLM Tuning tab (Settings) saves `llm.*` keys into `app_settings`
(category 'config'). Services historically read only `os.environ`, so the GUI
never actually controlled them. This resolver merges the DB settings OVER the
env defaults, so a change in the GUI takes effect (within CACHE_TTL) without an
edit to `.env` or a container recreate.

THIS IS THE ONLY COPY. It used to be duplicated verbatim into llm_query,
scan_recommender and autogen_agents because `common/` was not mounted into all
of them, with a test keeping the four byte-identical. That is the arrangement
`common/Dockerfile` exists to prevent: it records that `validation.py` once
lived in seven places and one had drifted with a real fix stranded in it.

The three services now bind-mount `./common` and import
`from common.llm_settings import get_llm_settings`, so there is one file to edit.

NOTE the import is soft at every call site (`except Exception: get_llm_settings
= None`), which means a broken import does not crash the service — it silently
falls back to env-only and the Settings → LLM Tuning GUI stops controlling that
service. tests/test_llm_settings_agreement.py therefore executes the import
INSIDE each container rather than trusting that the file is present.

No site-specific values belong here. Every `*_api_key` defaults to `""`; the
only URLs are the public vendor endpoint and the `ollama`/`vllm` service names.
Real endpoints and keys come from `app_settings` (DB) or the environment.

Never raises: a DB hiccup falls back to env/defaults so it cannot take the LLM
path down.
"""
import json
import os
import time

try:
    import psycopg2
except Exception:  # pragma: no cover - psycopg2 always present in services
    psycopg2 = None

CACHE_TTL = 30  # seconds

_cache = {"data": None, "ts": 0.0}

# resolver_key: (db_key_without_llm_prefix, env_var, default)
_FIELDS = {
    "backend":           ("backend",          "LLM_BACKEND",       "ollama"),
    "openai_api_base":   ("openai_base_url",  "OPENAI_API_BASE",   "https://api.openai.com"),
    "openai_model":      ("openai_model",     "OPENAI_MODEL",      "gpt-4o"),
    "openai_api_key":    ("openai_api_key",   "OPENAI_API_KEY",    ""),
    "azure_endpoint":    ("azure_endpoint",   "AZURE_ENDPOINT",    ""),
    "azure_model":       ("azure_model",      "AZURE_MODEL",       ""),
    "azure_api_key":     ("azure_api_key",    "AZURE_API_KEY",     ""),
    "azure_api_version": ("azure_api_version","AZURE_API_VERSION", "2024-08-01-preview"),
    "anthropic_model":   ("anthropic_model",  "ANTHROPIC_MODEL",   "claude-sonnet-4-20250514"),
    "anthropic_api_key": ("anthropic_api_key","ANTHROPIC_API_KEY", ""),
    "vllm_url":          ("vllm_url",         "VLLM_URL",          "http://vllm:8000"),
    "vllm_model":        ("vllm_model",       "VLLM_MODEL",        ""),
    "ollama_url":        ("ollama_url",       "OLLAMA_URL",        "http://ollama:11434"),
    "ollama_model":      ("ollama_model",     "OLLAMA_MODEL",      "qwen2.5:32b"),
}


# ---------------------------------------------------------------------------
# Per-task routing
# ---------------------------------------------------------------------------
# One model for the whole stack is wrong in both directions: the frontier model
# is wasted on "summarise this article and set five booleans", and a cheap model
# fumbles tool calls in the exploit phase. A route says which model (and
# optionally which BACKEND) a given task should use.
#
# Stored as `llm.route.<task>` in app_settings (category 'config'), so
# Settings -> LLM Tuning drives it; `LLM_ROUTE_<TASK>` is the env fallback.
# `llm.route.default` covers every task with no explicit entry, and with no
# default at all a task falls back to the global backend/model — i.e. exactly
# today's behaviour, which is what makes this safe to add.
#
# Value forms:
#   "claude-sonnet-5"          -> that model on the CURRENT backend
#   "azure:claude-sonnet-5"    -> that model, forced onto Azure
#   "ollama:qwen2.5:14b"       -> that model on a LOCAL ollama (note the model
#                                 tag itself contains a colon, which is why only
#                                 the first segment is treated as a backend and
#                                 only when it names one)
#   ""                         -> inherit (route.default, then the global model)

KNOWN_BACKENDS = ("azure", "openai", "anthropic", "ollama", "vllm")

# Named provider instances.
#
# The per-type keys (llm.azure_*, llm.openai_*, ...) allow exactly ONE config
# per backend type, so two Azure resources -- one serving DeepSeek, another
# serving Claude models -- cannot both be reachable. `llm.providers` holds a
# JSON array of named instances instead:
#
#   [{"id": "azure-main", "type": "azure",
#     "endpoint": "https://rt3ai.services.ai.azure.com/",
#     "api_key": "...", "api_version": "2024-08-01-preview",
#     "default_model": "DeepSeek-V4-Flash", "enabled": true},
#    {"id": "local", "type": "ollama",
#     "endpoint": "http://host.docker.internal:11434",
#     "default_model": "qwen2.5:14b"}]
#
# A route then names the INSTANCE: `azure-claude:claude-sonnet-5`.
#
# The per-type keys are still honoured as IMPLICIT providers whose id is the
# type name, so every existing route (`azure:...`) and every deployment with no
# llm.providers row keeps working unchanged.
PROVIDER_FIELDS = ("id", "type", "endpoint", "api_key", "api_version",
                   "default_model", "enabled")


def _implicit_providers(s):
    """One provider per backend type, from the legacy per-type keys.

    These are what every existing deployment has, so they must remain
    addressable by their type name or adding named instances would silently
    break routes that already work.
    """
    out = []
    for t in KNOWN_BACKENDS:
        if t == "azure":
            ep, key, model = s.get("azure_endpoint"), s.get("azure_api_key"), s.get("azure_model")
        elif t == "openai":
            ep, key, model = s.get("openai_api_base"), s.get("openai_api_key"), s.get("openai_model")
        elif t == "anthropic":
            ep, key, model = "", s.get("anthropic_api_key"), s.get("anthropic_model")
        elif t == "vllm":
            ep, key, model = s.get("vllm_url"), "", s.get("vllm_model")
        else:
            ep, key, model = s.get("ollama_url"), "", s.get("ollama_model")
        out.append({"id": t, "type": t, "endpoint": ep or "",
                    "api_key": key or "", "api_version": s.get("azure_api_version") or "",
                    "default_model": model or "", "enabled": True,
                    "implicit": True})
    return out


def get_providers(settings=None):
    """Every usable provider: explicit named instances first, then implicit.

    Never raises: malformed JSON in `llm.providers` falls back to the implicit
    set rather than taking every LLM path down, because a config typo must not
    be an outage. An explicit instance whose id collides with a type name wins
    -- the operator named it deliberately.
    """
    s = settings or get_llm_settings()
    explicit = []
    raw = s.get("providers")
    if raw:
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, dict):
                parsed = [parsed]
            for entry in (parsed or []):
                if not isinstance(entry, dict):
                    continue
                pid = str(entry.get("id") or "").strip()
                ptype = str(entry.get("type") or "").strip().lower()
                if not pid or ptype not in KNOWN_BACKENDS:
                    continue
                if entry.get("enabled") is False:
                    continue
                explicit.append({
                    "id": pid, "type": ptype,
                    "endpoint": (entry.get("endpoint") or "").strip(),
                    "api_key": entry.get("api_key") or "",
                    "api_version": entry.get("api_version") or "",
                    "default_model": (entry.get("default_model") or "").strip(),
                    "enabled": True, "implicit": False,
                })
        except Exception:
            explicit = []

    seen = {p["id"] for p in explicit}
    return explicit + [p for p in _implicit_providers(s) if p["id"] not in seen]


def get_provider(pid, settings=None):
    """One provider by id, or None."""
    pid = (pid or "").strip()
    if not pid:
        return None
    for p in get_providers(settings):
        if p["id"] == pid:
            return p
    return None

# Canonical task list. The UI renders one row per entry; a task absent from
# here still resolves (routes are just strings), but it will not be offered in
# the dropdown, so add new LLM consumers here.
LLM_TASKS = (
    ("recon",       "Reconnaissance agent — host/service discovery reasoning"),
    ("analyze",     "Analyzer agent — findings triage and correlation"),
    ("exploit",     "Exploit agent — exploit selection and chain construction"),
    ("scan",        "Scanner agent — scan planning and next-step selection"),
    ("postex",      "Post-exploitation review"),
    ("news",        "Security-news enrichment (high volume, low difficulty)"),
    ("recommend",   "Scan recommender — per-service tool suggestions"),
    ("exploit_gen", "Exploit/PoC script generation"),
    ("extract",     "Extractor learning — parsing tool output into fields"),
    ("triage",      "Cloud/artifact triage"),
    ("chat",        "Operator chat in the dashboard"),
)

LLM_TASK_NAMES = tuple(t for t, _ in LLM_TASKS)


def parse_route(raw, known_prefixes=None):
    """"<provider|backend>:<model>" | "<model>" | "" -> (prefix_or_None, model).

    Splits on the FIRST colon only, and only when that first segment names a
    known backend type OR a configured provider id -- otherwise the whole
    string is the model. Without that rule an ollama tag like "qwen2.5:14b"
    would be read as a provider called "qwen2.5".

    `known_prefixes` lets a caller add provider ids; with none, backend types
    are recognised, which keeps this usable as a pure function in tests.
    """
    raw = (raw or "").strip()
    if not raw:
        return None, ""
    known = {b.lower() for b in KNOWN_BACKENDS}
    known |= {str(k).lower() for k in (known_prefixes or ())}
    if ":" in raw:
        head, rest = raw.split(":", 1)
        if head.strip().lower() in known:
            # "ollama:" / "azure-main:" (no model) is valid and means "that
            # provider, with the model it is already configured with".
            return head.strip().lower(), rest.strip()
    return None, raw


def get_route(task, settings=None):
    """Resolve one task to {backend, model, source}.

    Never raises and never returns a partially-filled route: an unroutable task
    resolves to the global backend/model, which is the behaviour every consumer
    had before routing existed.
    """
    s = settings or get_llm_settings()
    routes = s.get("routes") or {}
    task = (task or "").strip()

    raw, source = "", "global"
    for candidate, src in ((routes.get(task), f"route.{task}"),
                           ((s.get("agent_models") or {}).get(task),
                            f"agent_model:{task}"),
                           (routes.get("default"), "route.default")):
        if candidate:
            raw, source = candidate, src
            break

    prov, model = _resolve_one(raw, s)
    backend = prov["type"]

    # Fallback: where to go when the primary is rate-limited past its retries.
    # Per-task entry first, then the global one. None means "no fallback" and
    # the 429 propagates, which is the correct default -- silently answering
    # from a different model than the operator selected, with no fallback
    # configured, would be worse than a visible failure.
    fbs = s.get("fallbacks") or {}
    fb_raw = fbs.get(task) or fbs.get("default") or ""
    fallback = None
    if fb_raw:
        fb_prov, fb_model = _resolve_one(fb_raw, s)
        # A fallback identical to the primary buys nothing but a second 429.
        # Compared on (provider id, model): the same model on a DIFFERENT
        # provider instance is a legitimate fallback, because it is a separate
        # deployment with its own quota.
        if (fb_prov["id"], fb_model) != (prov["id"], model):
            fallback = {"backend": fb_prov["type"], "model": fb_model,
                        "provider": fb_prov["id"], "endpoint": fb_prov["endpoint"],
                        "api_key": fb_prov["api_key"],
                        "api_version": fb_prov["api_version"],
                        "raw": fb_raw}

    return {"task": task, "backend": backend, "model": model,
            "provider": prov["id"], "endpoint": prov["endpoint"],
            "api_key": prov["api_key"], "api_version": prov["api_version"],
            "source": source, "raw": raw, "fallback": fallback}


def _resolve_one(raw, s):
    """One route string -> (provider_dict, model).

    The provider carries its own endpoint and key, which is what lets two
    instances of the SAME backend type (two Azure resources, say) both be
    reachable. With no prefix the globally-selected backend's provider is used,
    i.e. exactly the pre-provider behaviour.
    """
    providers = get_providers(s)
    by_id = {p["id"]: p for p in providers}
    prefix, model = parse_route(raw, known_prefixes=by_id.keys())

    if prefix and prefix in by_id:
        prov = by_id[prefix]
    else:
        active = (s.get("backend") or "ollama").lower()
        prov = by_id.get(active) or (providers[0] if providers else
                                     {"id": active, "type": active,
                                      "endpoint": "", "api_key": "",
                                      "api_version": "", "default_model": "",
                                      "enabled": True, "implicit": True})
    if not model:
        model = prov.get("default_model") or ""
    return prov, model


def _read_db_llm():
    dsn = os.environ.get("DB_DSN")
    if not dsn or psycopg2 is None:
        return {}
    out = {}
    conn = None
    try:
        conn = psycopg2.connect(dsn, connect_timeout=3)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT key, value FROM app_settings "
                "WHERE key LIKE 'llm.%%' AND category = 'config'"
            )
            for key, value in cur.fetchall():
                if value not in (None, ""):
                    out[key[4:]] = value  # strip the 'llm.' prefix
            # Bridge the OLDER per-agent selection: rag-api's
            # /settings/agent-models stores `agent_model:<id>` under
            # category='agent_model'. It predates routing, covers a disjoint
            # set of agents (cloud_triage_agent, gap_agent, ...) and has no
            # backend or fallback -- but an operator who already picked a model
            # there must not have it silently ignored once routing exists. Read
            # as a LOWER-precedence source than llm.route.<task>.
            cur.execute(
                "SELECT key, value FROM app_settings "
                "WHERE key LIKE 'agent_model:%%' AND category = 'agent_model'"
            )
            for key, value in cur.fetchall():
                if value not in (None, ""):
                    out["agentmodel." + key.split(":", 1)[1]] = value
    except Exception:
        return {}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
    return out


def get_llm_settings(force_refresh=False):
    """Merged config: DB `llm.*` wins over env, else env, else default.

    Returns a dict of resolver keys (see _FIELDS) plus `_source` mapping each
    key to 'db' | 'env' | 'default' for diagnostics. Cached CACHE_TTL seconds.
    """
    now = time.time()
    if (not force_refresh and _cache["data"] is not None
            and (now - _cache["ts"]) < CACHE_TTL):
        return _cache["data"]

    db = _read_db_llm()
    merged = {}
    source = {}
    for rk, (db_key, env_var, default) in _FIELDS.items():
        if db.get(db_key):
            merged[rk], source[rk] = db[db_key], "db"
        elif os.environ.get(env_var):
            merged[rk], source[rk] = os.environ[env_var], "env"
        else:
            merged[rk], source[rk] = default, "default"
    # Routes are free-form keys (`llm.route.<task>`), not part of _FIELDS, so
    # they have to be carried explicitly or _read_db_llm's work is discarded.
    routes, fallbacks = {}, {}
    for k, v in db.items():
        if not k.startswith("route.") or not v:
            continue
        name = k[len("route."):]
        if name.endswith(".fallback"):
            fallbacks[name[: -len(".fallback")]] = v
        else:
            routes[name] = v
    for task in LLM_TASK_NAMES + ("default",):
        if task not in routes:
            ev = os.environ.get(f"LLM_ROUTE_{task.upper()}")
            if ev:
                routes[task] = ev
        if task not in fallbacks:
            ev = os.environ.get(f"LLM_ROUTE_{task.upper()}_FALLBACK")
            if ev:
                fallbacks[task] = ev
    # A single global fallback is the common case: "when the primary is rate
    # limited, use this instead". LLM_ROUTE_FALLBACK sets it without a DB row.
    if "default" not in fallbacks and os.environ.get("LLM_ROUTE_FALLBACK"):
        fallbacks["default"] = os.environ["LLM_ROUTE_FALLBACK"]
    merged["routes"] = routes
    merged["fallbacks"] = fallbacks
    merged["providers"] = db.get("providers") or os.environ.get("LLM_PROVIDERS") or ""
    merged["agent_models"] = {
        k[len("agentmodel."):]: v for k, v in db.items()
        if k.startswith("agentmodel.") and v
    }

    merged["_source"] = source
    _cache["data"] = merged
    _cache["ts"] = now
    return merged


def clear_cache():
    _cache["data"] = None
    _cache["ts"] = 0.0
