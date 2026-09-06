"""Guards for the class of defect that kept CI permanently red.

WHY THIS EXISTS
---------------
CI on `main` failed on every run, so a genuinely NEW failure was invisible —
CLAUDE.md's own rule ("keep the suite green; a permanently red baseline means a
new failure is invisible") had no test behind it. 21 of the 23 failures were one
copy-pasted bug: a `docker exec` helper that returned its "cannot run here"
sentinel ONLY when the subprocess RAISED. On a runner where docker exists but no
stack is up, `docker exec` instead EXITS 1 with "No such container", which the
helpers turned into a hard failure. The skip never fired.

The fix is centralised in tests/_container.py. This module stops a private copy
of the broken shape from reappearing — the reason it cost 21 tests the first
time is that five modules each had their own.

Sabotage check: re-inline a raw `subprocess.run(["docker", "exec", ...])` in any
tests/*.py without consulting the returncode -> test_no_private_docker_exec RED.
"""
import ast
import os
import pathlib

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
HELPER = TESTS / "_container.py"

#: Modules that still call `docker exec` directly instead of going through
#: tests/_container.py. A RATCHET, in the style of SCOPE_DEBT / PROXY_DEBT /
#: SQL_DEBT: a NEW module doing this fails by name, and an entry that gets
#: migrated must be DELETED (test_the_debt_list_has_no_stale_entries enforces
#: that, so the list can only shrink).
#:
#: These are grandfathered on EVIDENCE, not assumption: the CI run that exposed
#: this whole class of bug (docker present, no stack up) failed in exactly eight
#: modules, none of them these — so they already distinguish "unreachable" from
#: "broken" by their own means. They are debt because the logic is duplicated
#: ~20 times, not because they are known-wrong.
DIRECT_EXEC_DEBT = {
    "test_artifact_consumer.py",
    "test_asset_merge.py",
    "test_asset_port_normalization.py",
    "test_candidate_space.py",
    "test_credential_bridge.py",
    "test_credential_secret_storage.py",
    "test_dead_parsers.py",
    "test_export_completeness.py",
    "test_findings_rollup.py",
    "test_fingerprint.py",
    "test_follow_up_export.py",
    "test_identity_credential_state.py",
    "test_infrastructure_rollup_export.py",
    "test_llm_settings_agreement.py",
    "test_post_review.py",
    "test_scan_parameters.py",
    "test_severity_scale.py",
    "test_tool_command_check.py",
    "test_tool_docs_fetch.py",
    "test_tool_invocations.py",
}


#: Never listed as debt: these are correct by construction.
DIRECT_EXEC_OK = {
    "_container.py",             # the shared helper itself
    "test_target_wordlists.py",  # consults returncode + is_unreachable()
}


def _docker_exec_calls(tree):
    """Yield ast.Call nodes that shell out to `docker exec`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for arg in node.args:
            if not isinstance(arg, (ast.List, ast.Tuple)):
                continue
            parts = [e.value for e in arg.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(parts) >= 2 and parts[0] == "docker" and parts[1] == "exec":
                yield node


def test_the_shared_helper_exists():
    assert HELPER.exists(), "tests/_container.py is gone — the guard below is vacuous"
    src = HELPER.read_text(encoding="utf-8")
    assert "UNREACHABLE_MARKERS" in src and "no such container" in src, \
        "the helper no longer recognises an absent container"


def test_no_private_docker_exec():
    """No NEW test module re-implements the container call. One place to be right."""
    offenders = []
    for path in sorted(TESTS.glob("test_*.py")):
        if path.name in DIRECT_EXEC_OK or path.name in DIRECT_EXEC_DEBT:
            continue
        if path.name == os.path.basename(__file__):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:                 # a broken file is another test's problem
            continue
        if any(_docker_exec_calls(tree)):
            offenders.append(path.name)
    assert not offenders, (
        "these modules call `docker exec` directly instead of using "
        f"tests/_container.container_exec(): {offenders}. A private copy is how the "
        "absent-container skip was missed in five modules at once. Use the helper, "
        "or add the name to DIRECT_EXEC_DEBT with a reason."
    )


def test_the_debt_list_has_no_stale_entries():
    """A migrated module must be REMOVED from the list, or the ratchet rusts."""
    stale = []
    for name in sorted(DIRECT_EXEC_DEBT):
        path = TESTS / name
        if not path.exists():
            stale.append(f"{name} (file is gone)")
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        if not any(_docker_exec_calls(tree)):
            stale.append(f"{name} (no longer calls docker exec)")
    assert not stale, f"remove these from DIRECT_EXEC_DEBT: {stale}"


@pytest.mark.parametrize("stderr,unreachable", [
    ("Error response from daemon: No such container: rag-api", True),
    ("Cannot connect to the Docker daemon at unix:///var/run/docker.sock.", True),
    ("Error response from daemon: Container abc is not running", True),
    ('exec: "python3": executable file not found in $PATH', True),
    # A REAL failure must stay a failure — the whole point of the distinction.
    ("Traceback (most recent call last):\nNameError: name 'x' is not defined", False),
    ("psycopg2.OperationalError: could not connect to server", False),
    ("", False),
])
def test_unreachable_is_distinguished_from_broken(stderr, unreachable):
    from _container import is_unreachable
    assert is_unreachable(stderr) is unreachable, stderr


def test_absent_container_yields_none_not_an_error_string():
    """The exact CI condition: docker present, container absent -> skip, not fail."""
    from _container import container_exec
    import shutil
    if not shutil.which("docker"):
        pytest.skip("docker not installed — the raise path already returns None")
    out = container_exec("print('x')", container="claude-guard-absent-container", timeout=30)
    assert out is None, (
        f"expected None (skip) for an absent container, got {out!r} — the caller's "
        "`is None` skip would not fire and the test would report as a FAILURE"
    )
