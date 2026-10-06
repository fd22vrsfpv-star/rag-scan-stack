"""Startup TLS validation for uvicorn services.

WHY
---
`uvicorn.run(..., ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE"))`
does NOT fail when the files are missing, unreadable or empty — in some
configurations uvicorn silently binds plain HTTP on the same port, so the
service starts, `/health` returns 200 over HTTP, and callers that trust the
URL scheme (e.g. the BFF dialling `https://autogen-agents:8015`) hit a TLS
handshake error that surfaces as `500 Internal Server Error` in the UI.

A WSL2 Docker bind-mount drop on `/certs` triggered exactly this on
2026-10-06 (`autogen-agents` and `scan-recommender` started with `/certs`
mounted as an empty tmpfs instead of the host bind-mount). See the
corresponding OPEN_ITEMS entry at the time.

CONTRACT
--------
`require_tls_or_exit()` returns a `(ssl_certfile, ssl_keyfile)` tuple ready
to splat into `uvicorn.run(**{...})`:

- If BOTH SSL_CERTFILE and SSL_KEYFILE are unset → returns `(None, None)`.
  The service was never meant to serve TLS; carry on.
- If EITHER is set → BOTH must be set, must point to a readable, non-empty
  file. Otherwise raise SystemExit with a loud message naming the service,
  the missing variable, and the offending path. The service refuses to
  start rather than silently fall back to HTTP.

This is deliberately an exit, not a warning. A service that advertises
HTTPS and then serves HTTP has broken its contract with every caller.
"""
from __future__ import annotations

import os
import sys
from typing import Optional, Tuple

__all__ = ["require_tls_or_exit", "TLSStartupError"]


class TLSStartupError(SystemExit):
    """SystemExit subclass so callers can catch TLS-specific failures in tests
    without catching every SystemExit."""


def _loud(service: str, msg: str) -> "TLSStartupError":
    banner = "=" * 72
    full = (
        f"\n{banner}\n"
        f"[{service}] TLS STARTUP ABORT\n"
        f"{msg}\n"
        f"Refusing to fall back to plain HTTP — see common/tls_startup.py.\n"
        f"{banner}\n"
    )
    # Print to stderr so it survives even if the service's logger is misconfigured.
    print(full, file=sys.stderr, flush=True)
    return TLSStartupError(2)


def require_tls_or_exit(
    service: str,
    *,
    certfile_env: str = "SSL_CERTFILE",
    keyfile_env: str = "SSL_KEYFILE",
) -> Tuple[Optional[str], Optional[str]]:
    """Validate `SSL_CERTFILE` / `SSL_KEYFILE` and return a `(cert, key)` pair.

    Parameters
    ----------
    service:
        Short service name, included in error output for triage.
    certfile_env, keyfile_env:
        Env var names, overridable for test isolation.
    """
    certfile = os.environ.get(certfile_env) or None
    keyfile = os.environ.get(keyfile_env) or None

    # Neither set → explicit intent is plain HTTP. Allow it.
    if not certfile and not keyfile:
        return (None, None)

    # Partial config is a configuration bug.
    if bool(certfile) ^ bool(keyfile):
        missing = keyfile_env if certfile else certfile_env
        raise _loud(
            service,
            f"{missing} is unset but its partner is set — need BOTH for TLS.",
        )

    for role, path, var in (
        ("cert", certfile, certfile_env),
        ("key", keyfile, keyfile_env),
    ):
        if not os.path.isfile(path):
            raise _loud(
                service,
                f"{var}={path!r} does not exist (TLS {role} file missing). "
                f"Likely a dropped bind-mount — check that /certs resolves to the "
                f"host certs directory, not an empty tmpfs.",
            )
        try:
            size = os.path.getsize(path)
        except OSError as e:  # pragma: no cover - stat failure is rare
            raise _loud(service, f"{var}={path!r} unreadable: {e}") from e
        if size <= 0:
            raise _loud(
                service,
                f"{var}={path!r} is empty (0 bytes) — a dropped bind-mount "
                f"materialises as an empty tmpfs with the same path.",
            )

    return (certfile, keyfile)
