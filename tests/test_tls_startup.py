"""Sabotage-provable guards for common/tls_startup.py.

The runtime bug this file prevents is: `/certs` ends up as an empty tmpfs
(bind-mount dropped), uvicorn is told `ssl_certfile=/certs/server.crt`,
uvicorn silently binds plain HTTP, every TLS caller 500s. See the matching
2026-10-06 CHANGES_MADE entry.

Run on demand:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_tls_startup.py -v'
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.tls_startup import TLSStartupError, require_tls_or_exit


REPO = Path(__file__).resolve().parent.parent


# ── unit cases ─────────────────────────────────────────────────────────────


def test_no_env_set_returns_none_tuple(monkeypatch):
    """Neither var set → service is HTTP-only by intent, allow it."""
    monkeypatch.delenv("SSL_CERTFILE", raising=False)
    monkeypatch.delenv("SSL_KEYFILE", raising=False)
    assert require_tls_or_exit("svc") == (None, None)


def test_missing_certfile_aborts(monkeypatch, tmp_path):
    key = tmp_path / "server.key"
    key.write_text("key-bytes")
    monkeypatch.setenv("SSL_CERTFILE", str(tmp_path / "does-not-exist.crt"))
    monkeypatch.setenv("SSL_KEYFILE", str(key))
    with pytest.raises(TLSStartupError):
        require_tls_or_exit("svc-under-test")


def test_empty_certfile_aborts(monkeypatch, tmp_path):
    """The ACTUAL 2026-10-06 scenario: /certs is a tmpfs so the cert file is
    0 bytes. A non-empty assertion catches it; isfile() alone would not."""
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("")  # 0 bytes
    key.write_text("key-bytes")
    monkeypatch.setenv("SSL_CERTFILE", str(cert))
    monkeypatch.setenv("SSL_KEYFILE", str(key))
    with pytest.raises(TLSStartupError):
        require_tls_or_exit("svc")


def test_partial_config_aborts(monkeypatch, tmp_path):
    cert = tmp_path / "server.crt"
    cert.write_text("cert")
    monkeypatch.setenv("SSL_CERTFILE", str(cert))
    monkeypatch.delenv("SSL_KEYFILE", raising=False)
    with pytest.raises(TLSStartupError):
        require_tls_or_exit("svc")


def test_happy_path_returns_both_paths(monkeypatch, tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("cert-bytes")
    key.write_text("key-bytes")
    monkeypatch.setenv("SSL_CERTFILE", str(cert))
    monkeypatch.setenv("SSL_KEYFILE", str(key))
    assert require_tls_or_exit("svc") == (str(cert), str(key))


# ── structural: every uvicorn service calls the guard ─────────────────────

# Services that call uvicorn.run with ssl_* kwargs MUST call
# require_tls_or_exit() first. If someone adds another one and forgets, this
# test names the file.
TLS_SERVICE_FILES = [
    "autogen_agents/autogen_service.py",
    "nuclei/nuclei_runner.py",
    "kali_listener/listener_service.py",
    "osint_runner/osint_runner.py",
    "pd_runner/pd_runner.py",
    "brutus_runner/brutus_runner.py",
    "web_scanner/web_scan.py",
    "scan_recommender/scan_recommender.py",
]


@pytest.mark.parametrize("rel_path", TLS_SERVICE_FILES)
def test_service_calls_require_tls_or_exit_before_uvicorn(rel_path):
    src = (REPO / rel_path).read_text()
    assert "require_tls_or_exit" in src, (
        f"{rel_path} runs uvicorn with ssl_* kwargs but does not call "
        f"require_tls_or_exit from common.tls_startup — a dropped /certs "
        f"bind-mount will silently serve plain HTTP."
    )
    # Must appear BEFORE uvicorn.run — the guard is not useful after.
    guard_pos = src.index("require_tls_or_exit(")
    run_match = re.search(r"uvicorn\.run\(", src)
    assert run_match is not None, f"{rel_path}: no uvicorn.run call found"
    assert guard_pos < run_match.start(), (
        f"{rel_path}: require_tls_or_exit must be called BEFORE uvicorn.run"
    )


def test_no_new_services_bypass_the_guard():
    """Ratchet: anyone adding another `uvicorn.run(..., ssl_certfile=...)` call
    must either call the guard or add themselves to TLS_SERVICE_FILES."""
    hits: list[str] = []
    for root, _dirs, files in os.walk(REPO):
        # Skip vendor + venv + node_modules + git
        if any(seg in root for seg in (".git", "node_modules", ".venv", ".helix", ".claude")):
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            p = Path(root) / name
            # Skip the helper + its test + this test file
            if p == REPO / "common/tls_startup.py" or p == Path(__file__):
                continue
            try:
                body = p.read_text(errors="ignore")
            except OSError:
                continue
            if re.search(r"uvicorn\.run\s*\([^)]*ssl_certfile", body):
                rel = str(p.relative_to(REPO))
                if rel not in TLS_SERVICE_FILES:
                    hits.append(rel)
    assert not hits, (
        f"new uvicorn+TLS services not declared in TLS_SERVICE_FILES: {hits}"
    )
