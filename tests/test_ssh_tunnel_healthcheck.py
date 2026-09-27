"""An unconfigured ssh-tunnel must report HEALTHY, not `unhealthy`.

The `ssh-tunnel` service starts by default but is unused unless SSH_REMOTE_HOST
is set (the live DB mode is `remote_direct`, which uses SSL directly and needs no
tunnel). Its healthcheck used to be

    [ -n "$SSH_REMOTE_HOST" ] && nc -z 127.0.0.1 ${SSH_SOCKS_PORT:-1080} || exit 1

so an empty SSH_REMOTE_HOST took the `|| exit 1` branch and the container sat
`Up (unhealthy)` forever. That is the repo's recurring "cannot run" reported as
"failed": it trains operators to ignore container health and makes
`docker ps --filter health=unhealthy` useless.

The fix makes the check exit 0 ("nothing to do") when SSH_REMOTE_HOST is empty
and only probe the SOCKS port when a host IS configured, so `unhealthy` is
reserved for a configured-but-broken tunnel.

This test is static: it reads docker-compose.yml and evaluates the healthcheck
shell logic. No docker, no running stack, no project imports — it works on a bare
checkout and in CI.

Sabotage check: revert the healthcheck to the `&& ... || exit 1` form and both
`test_unconfigured_tunnel_is_healthy` and `test_empty_host_snippet_exits_zero`
fail.

    pytest tests/test_ssh_tunnel_healthcheck.py -q
"""

import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip(
    "yaml", reason="pyyaml not installed — cannot parse docker-compose.yml"
)

REPO = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO / "docker-compose.yml"


def _healthcheck_test() -> str:
    """Return the ssh-tunnel healthcheck CMD-SHELL string from docker-compose.yml."""
    if not COMPOSE_FILE.exists():
        pytest.skip(f"{COMPOSE_FILE} not found")
    data = yaml.safe_load(COMPOSE_FILE.read_text())
    services = (data or {}).get("services", {})
    svc = services.get("ssh-tunnel")
    if not svc:
        pytest.skip("ssh-tunnel service not present in docker-compose.yml")
    hc = svc.get("healthcheck") or {}
    test = hc.get("test")
    if not test:
        pytest.skip("ssh-tunnel has no healthcheck")
    # test is ["CMD-SHELL", "<snippet>"] or a bare string
    if isinstance(test, list):
        assert test and test[0] in ("CMD-SHELL", "CMD"), test
        return test[-1]
    return str(test)


def _as_shell(snippet: str) -> str:
    """docker-compose escapes literal '$' as '$$'; undo it to run under /bin/sh."""
    return snippet.replace("$$", "$")


def test_healthcheck_references_remote_host():
    """The check must branch on SSH_REMOTE_HOST — that is what 'configured' means."""
    snippet = _healthcheck_test()
    assert "SSH_REMOTE_HOST" in snippet, snippet


def test_unconfigured_tunnel_is_healthy():
    """Structural: the empty-host path must NOT force a non-zero exit.

    The old bug was a trailing `|| exit 1` that fired whenever the AND-chain was
    false — including when SSH_REMOTE_HOST was empty. The fixed form guards the
    probe behind the host being set (`[ -z HOST ] || nc ...`), so no `exit 1`.
    """
    snippet = _healthcheck_test()
    assert "exit 1" not in snippet, (
        "healthcheck still contains `exit 1`; an unconfigured tunnel "
        f"(empty SSH_REMOTE_HOST) would be reported unhealthy: {snippet!r}"
    )


def test_empty_host_snippet_exits_zero():
    """Behavioural: running the snippet with SSH_REMOTE_HOST='' returns 0."""
    snippet = _as_shell(_healthcheck_test())
    proc = subprocess.run(
        ["sh", "-c", snippet],
        env={"SSH_REMOTE_HOST": "", "PATH": "/usr/bin:/bin"},
        capture_output=True,
    )
    assert proc.returncode == 0, (
        f"unconfigured tunnel should be healthy (exit 0), got {proc.returncode}: "
        f"{proc.stderr.decode(errors='replace')}"
    )


def test_configured_but_dead_tunnel_is_unhealthy():
    """Behavioural: with a host set and no SOCKS listener, the probe fails.

    Uses an unlikely-to-be-open port so the `nc -z` probe returns non-zero,
    proving `unhealthy` is still reported for a configured-but-broken tunnel.
    """
    if subprocess.run(["sh", "-c", "command -v nc"], capture_output=True).returncode != 0:
        pytest.skip("nc (netcat) not available on host")
    snippet = _as_shell(_healthcheck_test())
    proc = subprocess.run(
        ["sh", "-c", snippet],
        env={
            "SSH_REMOTE_HOST": "example.invalid",
            "SSH_SOCKS_PORT": "1",  # nothing listens on 127.0.0.1:1
            "PATH": "/usr/bin:/bin",
        },
        capture_output=True,
    )
    assert proc.returncode != 0, (
        "a configured tunnel with no live SOCKS port should be unhealthy "
        f"(non-zero), got {proc.returncode}"
    )
