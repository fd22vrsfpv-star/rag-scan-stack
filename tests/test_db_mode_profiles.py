"""In a remote DB mode the local postgres must not run — one alias, one server.

WHY THIS EXISTS
---------------
In remote / remote_direct mode the `rag-db-tunnel` sidecar takes the
`rag-postgres` network alias and forwards to the remote database. If the LOCAL
postgres also runs, BOTH answer to `rag-postgres`, Docker DNS hands out both
addresses, and ~half of all connections land on the local server — which has no
SSL — and fail with "server does not support SSL, but SSL was required". A whole
session's worth of intermittent DB failures (aborted access probes, a web
pipeline dying at the scope gate, nikto ingesting nothing) traced to exactly
this split brain.

The trigger: `.env` shipped `COMPOSE_PROFILES=local-db`, so ANY `docker compose
up` reconciled the local-db profile and started the local postgres — and
setup.sh's old guard keyed the decision off whether DB_DSN mentioned
`rag-postgres`, which it ALWAYS does in remote mode (the tunnel uses that name),
so the guard was fooled and left local-db on.

These are static source guards; no docker or DB needed.

SABOTAGE PROOF
--------------
Restore setup.sh's `! echo "$DSN_LINE" | grep -q "rag-postgres"` heuristic and
test_setup_decides_local_db_by_mode fails. Drop the local-postgres stop from
refresh-db-connection.sh and test_refresh_stops_local_pg_in_remote fails.
"""
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SETUP = os.path.join(REPO, "scripts", "setup.sh")
REFRESH = os.path.join(REPO, "scripts", "optional", "refresh-db-connection.sh")
CHECK = os.path.join(REPO, "scripts", "post-install-check.sh")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_setup_decides_local_db_by_mode():
    """The profile decision keys off the db-config MODE, not the DSN hostname —
    the DSN mentions rag-postgres in remote mode too, so that heuristic was
    wrong."""
    src = _read(SETUP)
    assert 'DB_MODE=' in src and 'db-config' in src.lower(), (
        "setup.sh no longer reads the db-config mode to decide local-db")
    assert 'remote_direct' in src, "remote_direct mode is not handled"
    # The fooled heuristic must be gone.
    assert 'DB_DSN does not reference rag-postgres' not in src, (
        "the DSN-hostname heuristic is back — it is fooled by the tunnel using "
        "the rag-postgres alias, and re-enables the split brain")


def test_setup_disables_local_db_in_remote():
    src = _read(SETUP)
    # In a remote mode it clears COMPOSE_PROFILES (so local-db is not started).
    i = src.find('DB_MODE" = "remote')
    assert i != -1, "setup.sh does not branch on a remote mode"
    window = src[i:i + 800]
    assert 'COMPOSE_PROFILES=""' in window, (
        "remote mode does not disable the local-db profile")


def test_refresh_stops_local_pg_in_remote():
    """The operator's mode-change script must clear local-db AND stop a
    still-running local postgres, or the alias stays split."""
    src = _read(REFRESH)
    assert 'remote_direct' in src, "refresh script does not handle remote_direct"
    assert 'local-db' in src and 'COMPOSE_PROFILES' in src, (
        "refresh does not strip local-db from COMPOSE_PROFILES in remote mode")
    assert 'rag-postgres' in src and 'docker stop' in src, (
        "refresh does not stop the local rag-postgres in remote mode")


def test_post_install_check_flags_the_split_brain():
    """The verifier must fail when more than one container answers to the
    rag-postgres alias — that is the split brain, made visible."""
    src = _read(CHECK)
    assert 'rag-postgres alias claimed by' in src, (
        "post-install-check no longer detects multiple alias owners")
    assert 'ALIAS_N' in src
