"""The DB-backed tests must stay runnable, and must not leak the password.

Run on demand:

    pytest tests/test_db_test_runner.py -v

WHY THIS EXISTS
---------------
Roughly 30 tests reported "no database at postgresql://app:app@localhost:5433/scans"
and could NEVER have run, for two independent reasons:

  1. rag-postgres publishes no host port. docker-compose.yml carries
     `# ports: ["5432:5432"]  # Disabled external port` — a deliberate decision,
     and the right one for a database in a pentest stack.
  2. pg_hba requires scram-sha-256 for anything but loopback inside the
     container, so the hard-coded `app:app` would have failed authentication
     even with a port open.

They skipped cleanly, the suite stayed green, and the dedup triggers, the raw
artifact queue and the jobs API were exercised nowhere. `scripts/run_db_tests.sh`
makes them runnable without a standing port: a throwaway loopback-only forwarder,
torn down on every exit path.

    60 passed / 38 skipped   ->   98 passed / 0 skipped

Uncovering that also surfaced three genuinely broken tests whose failure was
disguised as missing infrastructure — see test_phase0_jobs.py.
"""
import os
import re
import stat

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
RUNNER = os.path.join(REPO, "scripts", "run_db_tests.sh")

# Every module that talks to a real database through the runner.
DB_MODULES = (
    "tests/test_db_dedup_integration.py",
    "tests/test_raw_artifacts.py",
    "tests/test_web_scan_parsers.py",
    "tests/test_phase0_jobs.py",
)


@pytest.mark.unit
def test_runner_exists_and_is_executable():
    assert os.path.exists(RUNNER), "scripts/run_db_tests.sh is gone"
    assert os.stat(RUNNER).st_mode & stat.S_IXUSR, "run_db_tests.sh is not executable"


@pytest.mark.unit
def test_runner_never_exposes_the_database_to_the_network():
    """A pentest stack must not put its own database on 0.0.0.0.

    The compose file disabled the port on purpose; the runner exists so the
    tests can run WITHOUT undoing that decision.
    """
    src = open(RUNNER, encoding="utf-8").read()
    assert 'HOST_BIND="${DB_TEST_BIND:-127.0.0.1}"' in src, \
        "the forwarder's default bind address is no longer loopback"
    assert '-p "${HOST_BIND}:${HOST_PORT}:5432"' in src, \
        "the published port is no longer pinned to the bind address"
    assert not re.search(r'-p\s+"?0\.0\.0\.0', src), "the runner binds 0.0.0.0"


@pytest.mark.unit
def test_runner_tears_the_forwarder_down_on_every_exit_path():
    """A leaked forwarder is a standing open port nobody knows about."""
    src = open(RUNNER, encoding="utf-8").read()
    assert re.search(r"trap cleanup EXIT INT TERM", src), \
        "no trap: an interrupted run leaves the database exposed"
    assert "docker rm -f" in src


@pytest.mark.unit
def test_runner_reads_the_real_password_rather_than_assuming_app_app():
    src = open(RUNNER, encoding="utf-8").read()
    assert "POSTGRES_PASSWORD" in src, \
        "the runner no longer reads the real password; scram-sha-256 will reject app:app"
    assert "postgresql://${PGUSER}:${PGPASS}@" in src


@pytest.mark.unit
def test_compose_still_keeps_the_database_port_closed():
    """If someone uncomments it, this fires — the runner made that unnecessary."""
    src = open(os.path.join(REPO, "docker-compose.yml"), encoding="utf-8").read()
    lines = src.splitlines()
    start = next(i for i, l in enumerate(lines) if l == "  rag-postgres:")
    # Stop at the next service key: a line indented by EXACTLY two spaces.
    # Splitting on "\n  " instead swallows the whole block, because every
    # 4-space body line starts with "\n  " too — which is why this test passed
    # while the port was reopened.
    block = []
    for l in lines[start + 1:]:
        if l.strip() and not l.startswith("   ") and l.startswith("  "):
            break
        block.append(l)
    assert any("image:" in l for l in block), \
        "failed to read the rag-postgres block; the guard would be vacuous"
    live = [l for l in block
            if l.strip().startswith("ports:") or l.strip().startswith("- \"5432")]
    assert not live, (
        f"rag-postgres publishes a host port again: {live} — use "
        "scripts/run_db_tests.sh instead of a standing exposure")


@pytest.mark.unit
@pytest.mark.parametrize("rel", DB_MODULES)
def test_every_db_module_honours_TEST_DB_DSN(rel):
    """The runner sets one env var; a module that ignores it silently skips."""
    src = open(os.path.join(REPO, rel), encoding="utf-8").read()
    assert "TEST_DB_DSN" in src, f"{rel} does not read TEST_DB_DSN"


@pytest.mark.unit
@pytest.mark.parametrize("rel", DB_MODULES)
def test_db_modules_agree_on_the_default_port(rel):
    """Two modules defaulted to 5432 and two to 5433.

    Nothing listens on either without the runner, so the disagreement was
    invisible — but it means a hand-set port fixes half the suite and not the
    other half.
    """
    src = open(os.path.join(REPO, rel), encoding="utf-8").read()
    ports = set(re.findall(r"postgresql://[^\"'\s]*?@[^\"'\s:]+:(\d+)/", src))
    assert ports <= {"5433"}, (
        f"{rel} defaults to port(s) {sorted(ports)}; the runner publishes 5433")


@pytest.mark.unit
@pytest.mark.parametrize("rel", DB_MODULES)
def test_skip_messages_do_not_print_the_password(rel):
    """Skip text reaches CI logs.

    Before the redaction the message read
    "no database at postgresql://app:R88APm8uB7DwJ3WUYdXuKhGznT07le6d@..." —
    the live password, in plain test output.
    """
    src = open(os.path.join(REPO, rel), encoding="utf-8").read()
    for m in re.finditer(r"pytest\.skip\(f?\"([^\"]*)\"", src):
        msg = m.group(1)
        if "{" not in msg:
            continue
        for var in re.findall(r"\{([A-Za-z_][A-Za-z0-9_.]*)", msg):
            if var.lower().endswith(("dsn", "url")):
                assert "_redact" in src, (
                    f"{rel} interpolates {var} into a skip message with no "
                    "_redact() helper — that prints the live password")
                assert f"_redact({var})" in src, (
                    f"{rel} prints raw {var} in a skip message; wrap it in _redact()")
