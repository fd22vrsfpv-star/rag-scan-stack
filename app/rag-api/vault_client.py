"""Vault-backed secret accessor with env-var fallback.

Usage:
    from vault_client import get_secret
    api_key = get_secret("rag-api", "API_KEY")

Resolution order:
    1. Vault KV v2 at `secret/data/<path>` if VAULT_ADDR + VAULT_TOKEN set
    2. Environment variable `<key>`
    3. `default` argument

Vault values are cached in-process for VAULT_CACHE_TTL seconds (default 300)
to avoid hammering Vault on hot paths. Call `clear_secret_cache()` after
rotating a secret.

Token sources (first non-empty wins):
    - VAULT_TOKEN env
    - /vault/init/init.json  (the file vault-init writes)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("secrets")

_VAULT_ADDR = os.environ.get("VAULT_ADDR", "").rstrip("/")
_VAULT_VERIFY = os.environ.get("VAULT_SKIP_VERIFY", "true").lower() not in ("1", "true", "yes")
_VAULT_MOUNT = os.environ.get("VAULT_KV_MOUNT", "secret")
_VAULT_CACHE_TTL = float(os.environ.get("VAULT_CACHE_TTL", "300"))
_VAULT_INIT_FILE = Path(os.environ.get("VAULT_INIT_FILE", "/vault/init/init.json"))

_cache: dict[tuple[str, str], tuple[float, str]] = {}
_cache_lock = threading.Lock()
_token_cache: dict[str, str] = {}


def _get_token() -> Optional[str]:
    tok = os.environ.get("VAULT_TOKEN", "").strip()
    if tok:
        return tok
    if "file" in _token_cache:
        return _token_cache["file"]
    if _VAULT_INIT_FILE.is_file():
        try:
            data = json.loads(_VAULT_INIT_FILE.read_text())
            tok = (data.get("root_token") or "").strip()
            if tok:
                _token_cache["file"] = tok
                return tok
        except Exception as e:
            logger.warning("failed to read %s: %s", _VAULT_INIT_FILE, e)
    return None


def _vault_enabled() -> bool:
    return bool(_VAULT_ADDR and _get_token())


def _vault_fetch(path: str, key: str) -> Optional[str]:
    """Fetch secret/data/<path> and return [key]. None on miss/error."""
    token = _get_token()
    if not (_VAULT_ADDR and token):
        return None
    url = f"{_VAULT_ADDR}/v1/{_VAULT_MOUNT}/data/{path.lstrip('/')}"
    try:
        r = requests.get(url, headers={"X-Vault-Token": token},
                         verify=_VAULT_VERIFY, timeout=5)
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            logger.warning("vault GET %s → %d", path, r.status_code)
            return None
        data = r.json().get("data", {}).get("data", {})
        val = data.get(key)
        return str(val) if val is not None else None
    except requests.RequestException as e:
        logger.warning("vault fetch %s/%s failed: %s", path, key, e)
        return None


def get_secret(path: str, key: str, default: Optional[str] = None) -> Optional[str]:
    """Return secret value for (path, key).

    `path` is the KV v2 path under the mount (e.g. "rag-api"). `key` is the
    field within that secret (e.g. "API_KEY").
    """
    cache_key = (path, key)
    now = time.time()
    with _cache_lock:
        cached = _cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]

    val: Optional[str] = None
    if _vault_enabled():
        val = _vault_fetch(path, key)

    if val is None:
        val = os.environ.get(key)

    if val is None:
        return default

    with _cache_lock:
        _cache[cache_key] = (now + _VAULT_CACHE_TTL, val)
    return val


def put_secret(path: str, data: dict[str, str]) -> bool:
    """Write/update KV v2 secret at `path`. Returns True on success."""
    token = _get_token()
    if not (_VAULT_ADDR and token):
        return False
    url = f"{_VAULT_ADDR}/v1/{_VAULT_MOUNT}/data/{path.lstrip('/')}"
    try:
        r = requests.post(url, headers={"X-Vault-Token": token},
                          json={"data": data}, verify=_VAULT_VERIFY, timeout=5)
        ok = r.status_code in (200, 204)
        if ok:
            with _cache_lock:
                # Invalidate any cached keys for this path
                for k in list(_cache):
                    if k[0] == path:
                        _cache.pop(k, None)
        else:
            logger.warning("vault PUT %s → %d: %s", path, r.status_code, r.text[:200])
        return ok
    except requests.RequestException as e:
        logger.warning("vault put %s failed: %s", path, e)
        return False


def clear_secret_cache() -> None:
    with _cache_lock:
        _cache.clear()


def vault_status() -> dict:
    return {
        "enabled": _vault_enabled(),
        "addr": _VAULT_ADDR,
        "mount": _VAULT_MOUNT,
        "token_source": "env" if os.environ.get("VAULT_TOKEN") else (
            "init_file" if _VAULT_INIT_FILE.is_file() else "none"
        ),
        "cache_ttl_s": _VAULT_CACHE_TTL,
        "cached_keys": len(_cache),
    }
