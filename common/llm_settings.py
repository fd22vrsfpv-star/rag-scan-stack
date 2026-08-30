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
    merged["_source"] = source
    _cache["data"] = merged
    _cache["ts"] = now
    return merged


def clear_cache():
    _cache["data"] = None
    _cache["ts"] = 0.0
