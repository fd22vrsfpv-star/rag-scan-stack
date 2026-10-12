"""Shared helper for tests that execute code inside a running service container.

WHY THIS EXISTS
---------------
Five test modules each inlined their own copy of::

    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script], ...)
    except (OSError, subprocess.SubprocessError):
        return None                       # "cannot run here" -> the fixture skips
    if out.returncode != 0:
        return f"__ERR__ {out.stderr}"    # "ran and broke"   -> the test fails

That returns ``None`` only when the call RAISES, which happens when the docker
binary is absent. On a CI runner docker exists and the daemon answers — there is
simply no stack up — so ``docker exec`` exits 1 with ``No such container:
rag-api``. That became an ``__ERR__`` string, the ``container`` fixture's skip
never fired, and 21 environment-unavailable tests reported as FAILURES.

CLAUDE.md: "Tests run standalone and skip cleanly when infrastructure or an
optional dependency is missing. A skip says 'cannot run here'; an error says
'broken', and mixing them hides real breakage." A permanently red baseline makes
a genuinely new failure invisible, which is exactly what happened.

Fixing it in one place (rather than five) is deliberate: `test_ci_baseline.py`
asserts no test module grows a private copy of the buggy pattern again.
"""
import subprocess

#: stderr fragments that mean "this environment cannot run container tests".
#: Anything NOT matched here is a real failure and must stay a failure — the
#: point of this module is to keep that distinction sharp, not to swallow errors.
UNREACHABLE_MARKERS = (
    "no such container",
    "no such object",
    "is not running",
    "cannot connect to the docker daemon",
    "error during connect",
    "permission denied while trying to connect to the docker daemon",
    "docker daemon is not running",
    "executable file not found",
)

ERR = "__ERR__"


def is_unreachable(stderr: str) -> bool:
    """True when stderr says the container/daemon is absent, not that code broke."""
    low = (stderr or "").lower()
    return any(m in low for m in UNREACHABLE_MARKERS)


def container_exec(script, container="rag-api", runner=("python3", "-c"),
                   timeout=120, stdin=False, tail=1200, timeout_is_error=False):
    """Run `script` inside `container`.

    Returns:
        None            — the container/daemon is unreachable (caller should SKIP).
                          Also a timeout, unless timeout_is_error=True.
        "__ERR__ ..."   — the command ran and failed  (caller should FAIL)
        str             — stdout on success
    """
    cmd = ["docker", "exec"] + (["-i"] if stdin else []) + [container] + list(runner) + [script]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # A TIMEOUT IS NOT UNREACHABILITY. The container answered; the command
        # just did not finish. Collapsing the two into None means a caller that
        # skips on None silently skips a genuine hang — the same "unreachable
        # reported as absent" mistake this module exists to prevent, inverted.
        #
        # Default stays None so the ~20 existing callers keep their behaviour;
        # opt in with timeout_is_error=True to tell the difference.
        if timeout_is_error:
            return f"{ERR} timed out after {timeout}s (the container WAS reachable)"
        return None
    except (OSError, subprocess.SubprocessError):
        # docker binary missing or unusable — genuinely cannot run here.
        return None
    if out.returncode != 0:
        if is_unreachable(out.stderr):
            return None
        return f"{ERR} {out.stderr.strip()[-tail:]}"
    return out.stdout


def container_available(container="rag-api") -> bool:
    """Cheap probe for a module-scoped fixture guard."""
    return container_exec("print('ok')", container=container, timeout=30) is not None

# ── Shared probes for SERVICE-backed test modules ──────────────────────────
#
# Nine modules added 2026-09-30..10-03 each carried a private copy of the same
# two helpers: a `_rag_api_up()` health probe and an `_in_container()` runner,
# both raw `subprocess.run(["docker","exec",...])`. That duplication is exactly
# what tests/test_ci_baseline.py::test_no_private_docker_exec exists to stop —
# five modules once shared a single broken copy, and it cost 21 tests at a
# stroke. It also put a literal service URL in nine test files, which
# tests/test_service_endpoints.py flags.
#
# Both now live here once. The URL below is executed INSIDE the container, so a
# literal localhost is correct (this file is declared in CONTAINER_INTERNAL for
# that reason) — a caller's own host-side URL still belongs in conftest.

#: Health endpoint as seen from INSIDE the service container.
SERVICE_HEALTH_URL = {
    "rag-api": "https://localhost:8000/health",
}


def service_healthy(container="rag-api", timeout=10) -> bool:
    """True when `container` is up AND its HTTP health endpoint answers 200.

    Distinguishes the three outcomes the repo keeps getting wrong: unreachable
    (container/daemon absent) and unhealthy (answered, not 200) both return
    False for a skipif guard, but neither is treated as a code failure.
    """
    url = SERVICE_HEALTH_URL.get(container)
    if not url:
        return container_available(container)
    out = container_exec(
        f"curl -sk {url} -o /dev/null -w '%{{http_code}}'",
        container=container, runner=("sh", "-lc"), timeout=timeout)
    return out is not None and not out.startswith("__ERR__") and out.strip() == "200"


def container_python(script, container="rag-api", timeout=15):
    """Run `script` with python3 inside `container`; return (stdout, stderr, rc).

    The tuple shape the nine migrated modules already assert against. Prefer
    `container_exec` in new code — it collapses unreachable to None so a caller
    cannot mistake "could not run" for "ran and produced nothing".
    """
    cmd = ["docker", "exec", container, "python3", "-c", script]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}", 127

def container_sh(script, container="rag-api", timeout=15, env=None):
    """Run `script` with `sh -lc` inside `container`; return (stdout, stderr, rc).

    The shell counterpart to `container_python`. Several modules shell out to
    curl inside rag-api so that $API_KEY and the service's own TLS endpoint are
    in scope; doing it here keeps the literal localhost URL out of nine test
    files (see tests/test_service_endpoints.py) and the raw docker exec out of
    all of them (tests/test_ci_baseline.py).
    """
    pre = []
    for k, v in (env or {}).items():
        pre += ["-e", f"{k}={v}"]
    cmd = ["docker", "exec"] + pre + [container, "sh", "-lc", script]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:  # noqa: BLE001
        return "", f"{type(e).__name__}: {e}", 127

