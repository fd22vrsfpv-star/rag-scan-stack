"""A small TTL cache for expensive queries, with refresh on demand.

WHY THIS EXISTS
---------------
The database is remote and `sslmode=require`. Measured 2026-10-15:

    fresh connect       317.6 ms
    query on open conn   45.7 ms

so even a pooled query costs ~46 ms over the WAN, and a wide one costs far more
(`/assets?limit=5000` takes **80 seconds**). Four services had already each
written the same cache to cope:

    nmap_scanner/nmap-api.py        _SCOPE_CACHE = {"rows": None, "at": 0.0}
    dashboard/bff/routers/scans.py  _SCOPE_CACHE = {"rows": None, "at": 0.0}
    etl/scope_gate.py               _ENFORCE_CACHE = {"rows": None, "at": 0.0}
    kali_listener/listener_service  _scope_cache  = {"rows": None, "at": 0.0}

Four copies, and **not one of them can be refreshed** — an operator who changes
the scope waits out the TTL with no way to say "no, re-read it now". That is the
gap this closes.

WHAT IT GUARANTEES
------------------
* **A refresh that FAILS does not erase what we had.** The loader raising is not
  evidence that the data is gone, so the previous value keeps being served and
  the failure is recorded. This is the repo's recurring rule — an answer that
  could not be obtained is its own outcome, never the negative one.
* **A failure is never cached.** Nothing stores an exception as a value, so the
  next call retries rather than serving an error for a whole TTL.
* **Age is always reportable.** A caller can tell the operator "cached, 12s old"
  instead of presenting stale data as fresh.
* **Every cache is addressable by name**, so one endpoint can list them all and
  bust one or all of them.

NOT A DATABASE. Process-local, lost on restart, not shared between services or
replicas. Use it for things that are expensive and tolerate being seconds old —
scope lists, tool manifests, asset summaries. Never for an authorization
decision: `etl/scope_gate.py` re-reads deliberately and fails closed.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("query_cache")

_REGISTRY: Dict[str, "QueryCache"] = {}
_REGISTRY_LOCK = threading.Lock()

_MISSING = object()


class QueryCache:
    """One named, TTL'd value with an explicit refresh.

        scope = QueryCache("scope_rows", ttl=30)
        rows  = scope.get(lambda: load_rows(cur))   # loads when stale
        scope.invalidate()                          # next get() re-reads
        rows  = scope.get(loader, force=True)       # re-read right now
    """

    def __init__(self, name: str, ttl: float = 30.0, stale_on_error: bool = True):
        self.name = name
        self.ttl = float(ttl)
        self.stale_on_error = bool(stale_on_error)
        self._value: Any = _MISSING
        self._loaded_at: float = 0.0
        # Staleness is a FLAG, not a zeroed timestamp. Zeroing _loaded_at made
        # age() return seconds-since-epoch, so a failed refresh logged
        # "serving the previous value, 1792019805s old" — a number that tells
        # the operator nothing and looks like corruption.
        self._stale: bool = False
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.stale_serves = 0
        self.load_errors = 0
        self.last_error: Optional[str] = None
        with _REGISTRY_LOCK:
            _REGISTRY[name] = self

    # -- reading ---------------------------------------------------------
    def age(self) -> Optional[float]:
        """Seconds since the value was loaded, or None if never loaded."""
        if self._value is _MISSING:
            return None
        return time.time() - self._loaded_at

    def is_fresh(self) -> bool:
        if self._stale:
            return False
        a = self.age()
        return a is not None and a < self.ttl

    def peek(self, default: Any = None) -> Any:
        """Whatever is held, fresh or not, without loading."""
        return default if self._value is _MISSING else self._value

    def get(self, loader: Callable[[], Any], force: bool = False) -> Any:
        """Return the cached value, loading via `loader` when stale or forced."""
        if not force and self.is_fresh():
            self.hits += 1
            return self._value
        with self._lock:
            # Another thread may have refreshed it while we waited.
            if not force and self.is_fresh():
                self.hits += 1
                return self._value
            try:
                value = loader()
            except Exception as e:  # noqa: BLE001
                self.load_errors += 1
                self.last_error = f"{type(e).__name__}: {e}"
                if self.stale_on_error and self._value is not _MISSING:
                    # A refresh that could not run is not evidence the data is
                    # gone. Keep serving what we had and say so.
                    self.stale_serves += 1
                    log.warning("query_cache %s: refresh failed (%s) — serving "
                                "the previous value, %.0fs old",
                                self.name, self.last_error, self.age() or 0)
                    return self._value
                raise
            self.misses += 1
            self._value = value
            self._loaded_at = time.time()
            self._stale = False
            return value

    # -- refreshing ------------------------------------------------------
    def invalidate(self) -> None:
        """Mark stale. The NEXT get() re-reads; nothing is dropped meanwhile.

        `_loaded_at` is deliberately left alone so `age()` keeps reporting how
        old the held value actually is — which is exactly what an operator
        needs to see while a refresh is failing.
        """
        with self._lock:
            self._stale = True

    def clear(self) -> None:
        """Forget the value entirely. `peek()` returns its default afterwards."""
        with self._lock:
            self._value = _MISSING
            self._loaded_at = 0.0
            self._stale = False

    # -- visibility ------------------------------------------------------
    def stats(self) -> dict:
        a = self.age()
        return {
            "name": self.name,
            "ttl_seconds": self.ttl,
            "age_seconds": None if a is None else round(a, 1),
            "fresh": self.is_fresh(),
            "marked_stale": self._stale,
            "loaded": self._value is not _MISSING,
            "hits": self.hits,
            "misses": self.misses,
            "stale_serves": self.stale_serves,
            "load_errors": self.load_errors,
            "last_error": self.last_error,
        }


# -- registry ------------------------------------------------------------
def get_cache(name: str, ttl: float = 30.0) -> QueryCache:
    """Fetch or create a named cache."""
    with _REGISTRY_LOCK:
        c = _REGISTRY.get(name)
    return c if c is not None else QueryCache(name, ttl=ttl)


def all_stats() -> list:
    with _REGISTRY_LOCK:
        caches = list(_REGISTRY.values())
    return [c.stats() for c in caches]


def invalidate(name: Optional[str] = None) -> list:
    """Refresh on demand. `name=None` marks every cache stale.

    Returns the names marked, so a caller can report what it actually did
    rather than claiming success for a name that does not exist.
    """
    with _REGISTRY_LOCK:
        caches = list(_REGISTRY.values())
    done = []
    for c in caches:
        if name is None or c.name == name:
            c.invalidate()
            done.append(c.name)
    return done
