"""The docker socket is opt-in in the scratch-db test runner, never default.

Run on demand:

    pytest tests/test_docker_sock_optin.py -v

WHY THIS EXISTS
---------------
`scripts/run_scratch_db_tests.sh` runs the whole suite against a throwaway
Postgres. The "docker-exec" test tier (~25 files that shell out to
`docker exec <service> python3 -c ...`) needs the host docker socket mounted
into the test container. Mounting the host docker socket grants full control of
the host docker daemon, so it MUST stay an explicit, default-OFF opt-in — never
mounted just by running the suite.

This is a pure source check: it reads the runner script text and asserts the
socket is not mounted unconditionally, and that the opt-in token gates the mount.
It skips cleanly if the script is absent, and needs no docker daemon.

SABOTAGE CHECK (proves the guard can fail)
------------------------------------------
Change the runner so the mount is unconditional, e.g. replace the guarded block
with a bare `SOCK_ARGS=(-v /var/run/docker.sock:/var/run/docker.sock)` outside
any `if [[ -n "${MOUNT_DOCKER_SOCK...`; `test_socket_not_mounted_by_default`
then fails. Restore to make it pass again.
"""
import os
import re
import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(REPO, "scripts", "run_scratch_db_tests.sh")
OPT_IN_TOKEN = "MOUNT_DOCKER_SOCK"
SOCK = "docker.sock"


def _source():
    if not os.path.isfile(RUNNER):
        pytest.skip(f"{RUNNER} not present")
    with open(RUNNER, "r", encoding="utf-8") as fh:
        return fh.read()


def _sock_mount_lines(src):
    """Lines that actually add the docker.sock bind-mount (a `-v .../docker.sock`
    argument), ignoring comments/usage/echo prose that merely mention it."""
    out = []
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if SOCK not in line:
            continue
        if re.search(r"-v\s*\S*docker\.sock", line):
            out.append(line)
    return out


def test_socket_not_mounted_by_default():
    """Every line that bind-mounts the socket must be gated by the opt-in.

    We assert the opt-in token appears in the same guarded block: each mount line
    lives under an `if [[ -n "${MOUNT_DOCKER_SOCK...` conditional, so with the
    variable unset no mount argument is produced.
    """
    src = _source()
    mount_lines = _sock_mount_lines(src)
    assert mount_lines, (
        "expected the runner to define a docker.sock mount (gated by the opt-in); "
        "none found — did the mechanism move?"
    )

    # The opt-in guard must exist and must reference the token.
    guard = re.search(
        r'if\s+\[\[\s*-n\s*"\$\{' + re.escape(OPT_IN_TOKEN) + r'[^}]*\}"\s*\]\]',
        src,
    )
    assert guard, (
        f"no `if [[ -n \"${{{OPT_IN_TOKEN}...}}\" ]]` guard found; the socket "
        f"mount must be gated by {OPT_IN_TOKEN}"
    )

    # Each mount line must sit AFTER the guard opener and inside a conditional
    # block — i.e. the guard's `if` precedes it and a matching `fi` follows it.
    guard_pos = guard.start()
    fi_after = src.find("\nfi", guard_pos)
    assert fi_after != -1, "opt-in guard block has no closing `fi`"
    for line in mount_lines:
        pos = src.find(line)
        assert guard_pos < pos < fi_after, (
            "docker.sock mount is not inside the MOUNT_DOCKER_SOCK opt-in block "
            f"(mounted unconditionally?): {line.strip()!r}"
        )


def test_opt_in_token_gates_the_mount():
    """The opt-in token and the socket mount are both present and associated."""
    src = _source()
    assert OPT_IN_TOKEN in src, f"opt-in token {OPT_IN_TOKEN} absent from runner"
    assert _sock_mount_lines(src), "no docker.sock bind-mount present in runner"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
