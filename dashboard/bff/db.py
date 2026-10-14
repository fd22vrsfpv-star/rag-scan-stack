"""Direct Postgres access for the BFF.

The BFF historically proxied every DB-touching operation through
scan_recommender or rag-api over HTTPS. That's clean for read-heavy endpoints
but adds a pointless round-trip for short, single-row writes the BFF owns the
trigger for -- most notably the scan_recommendations lifecycle (mark 'queued' on
dispatch, backfill 'completed' / 'failed' from the polling loop).

POOLED, as of 2026-10-15. The previous version opened a fresh connection per
call and said so: "Connections are short-lived (per call) -- no pooling -- which
is fine for the call rate this code path sees... If write volume grows we can
drop psycopg2.pool in here without changing callers." That growth happened. The
scope gate calls `aliases_for()` once per dispatch target, and each call opened
its own connection.

Measured against this stack's database (remote, sslmode=require):

    fresh connect       317.6 ms
    query on open conn   45.7 ms
    alias lookup query   48.6 ms

The handshake costs SEVEN TIMES the query it carries. A 760-target masscan
dispatch therefore spent minutes in the gate doing TLS handshakes before a
single packet left the stack; node-manager logged nothing and the BFF raised
httpx.ReadTimeout, which from outside is indistinguishable from a hung scanner.

rag-api has pooled for a long time (`_get_pool` in app/rag-api/api.py); this
mirrors it, including the staleness check, so the two services behave the same.
The `get_db()` contract is unchanged -- a context manager yielding a connection,
caller commits -- so none of the 25 call sites needed touching.
"""

from contextlib import contextmanager
import logging
import os
import threading

import psycopg2
from psycopg2.pool import ThreadedConnectionPool

from config import get_settings

log = logging.getLogger("bff.db")

_POOL: ThreadedConnectionPool | None = None
_POOL_LOCK = threading.Lock()
_POOL_MIN = int(os.environ.get("BFF_DB_POOL_MIN", "1"))
# The BFF is one process; the gate's batch loop is serial, so a handful of slots
# covers concurrent requests without holding connections the DB could give to
# rag-api, which does the heavy lifting.
_POOL_MAX = int(os.environ.get("BFF_DB_POOL_MAX", "10"))


def _get_pool() -> ThreadedConnectionPool:
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                s = get_settings()
                _POOL = ThreadedConnectionPool(
                    _POOL_MIN, _POOL_MAX,
                    host=s.db_host, port=s.db_port, dbname=s.db_name,
                    user=s.db_user, password=s.db_password,
                    connect_timeout=5,
                    # Same two guards rag-api uses. A caller that forgets to
                    # commit must not hold locks forever, and a contended write
                    # should shed rather than queue behind a leaked transaction.
                    options="-c idle_in_transaction_session_timeout=120000 "
                            "-c lock_timeout=15000",
                )
                log.info("BFF DB pool initialized: min=%d max=%d", _POOL_MIN, _POOL_MAX)
    return _POOL


def _alive(conn) -> bool:
    """A pooled connection can have been dropped while idle."""
    try:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True
    except Exception:
        return False


def _discard(pool, conn) -> None:
    try:
        pool.putconn(conn, close=True)
    except Exception:
        log.debug("discarding stale conn raised", exc_info=True)


@contextmanager
def get_db():
    """Yield a pooled psycopg2 connection.

    Caller is responsible for ``conn.commit()``. On exception the transaction is
    rolled back before the connection returns to the pool -- without that, a
    failed caller would hand back a connection in a failed transaction and the
    NEXT user of that slot would see `InFailedSqlTransaction` on an unrelated
    query. A per-call connection hid this by closing; a pooled one cannot.
    """
    pool = _get_pool()
    conn = pool.getconn()
    if not _alive(conn):
        log.info("BFF DB pool: discarded stale connection, fetching a fresh one")
        _discard(pool, conn)
        conn = pool.getconn()
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except Exception:
            log.debug("rollback on error raised", exc_info=True)
        raise
    finally:
        try:
            # Leave no open transaction behind, committed or not.
            if conn.status != psycopg2.extensions.STATUS_READY:
                conn.rollback()
        except Exception:
            log.debug("final rollback raised", exc_info=True)
        try:
            pool.putconn(conn)
        except Exception:
            log.debug("putconn raised", exc_info=True)
