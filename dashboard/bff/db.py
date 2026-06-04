"""
Direct Postgres access for the BFF.

The BFF historically proxied every DB-touching operation through scan_recommender or rag-api over HTTPS.  That's clean for read-heavy endpoints but adds a pointless round-trip for short, single-row writes the BFF owns the trigger for -- most notably the scan_recommendations lifecycle (mark 'queued' on dispatch, backfill 'completed' / 'failed' from the polling loop).

This module exposes a small ``get_db()`` context manager that mirrors the pattern used by scan_recommender.py.  Connections are short-lived (per call) -- no pooling -- which is fine for the call rate this code path sees (one write per dispatched rec + one per terminal job transition).  If write volume grows we can drop psycopg2.pool in here without changing callers.

The same DB env vars (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD) feed both scan_recommender and the BFF, so a single docker-compose env block keeps the two services pointed at the same Postgres.
"""

from contextlib import contextmanager
import logging

import psycopg2

from config import get_settings

log = logging.getLogger("bff.db")


@contextmanager
def get_db():
    """Yield a short-lived psycopg2 connection.

    Caller is responsible for ``conn.commit()``; the context manager only
    handles close-on-exit so a failing caller's transaction rolls back
    automatically when the connection drops.
    """
    s = get_settings()
    conn = psycopg2.connect(
        host=s.db_host,
        port=s.db_port,
        dbname=s.db_name,
        user=s.db_user,
        password=s.db_password,
        connect_timeout=5,
    )
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            log.debug("conn.close raised", exc_info=True)
