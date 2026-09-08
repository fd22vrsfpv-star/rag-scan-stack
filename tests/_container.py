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
