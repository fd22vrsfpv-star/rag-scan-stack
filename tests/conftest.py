"""
Pytest configuration and shared fixtures for all tests.
"""
import os
import sys
from pathlib import Path
from typing import Generator
import pytest
from unittest.mock import MagicMock

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# NOTE: do NOT add service directories (scan_recommender/, kali_listener/, ...)
# to sys.path here. Services intentionally contain same-named modules — e.g.
# both scan_recommender/log_manager.py and autogen_agents/log_manager.py exist —
# because each runs isolated in its own container. Putting them on a shared path
# makes `import log_manager` resolve to whichever came first, which silently
# skipped ~120 tests when tried. A test needing a service module should load it
# by explicit file path with importlib (see tests/test_artifact_actions.py).


# ---- Shared lab / fixture constants ----
#
# The lab target was written as a LITERAL in ~200 places across the suite, so
# moving the lab — or running the same tests against a different host — meant a
# 200-site edit. New tests import LAB_TARGET instead, and the env override lets
# the suite point somewhere else without touching code.
LAB_TARGET = os.environ.get("TEST_LAB_TARGET", "192.168.1.150")

# The host that appears INSIDE captured tool output under tests/ (crackmapexec
# banners, netexec ACCOUNT FOUND lines, whatweb output, ...). It is deliberately
# NOT env-overridable: those fixtures are recorded bytes, so an expected value
# compared against them must move only when the recording does. Using
# LAB_TARGET for these would mean setting TEST_LAB_TARGET silently breaks every
# test that parses a fixture — a trap that is worse than the literal it removes.
FIXTURE_HOST = "192.168.1.150"

# RFC 5737 documentation ranges. Fixtures use these for "other hosts" so a
# fixture can never name something routable by accident.
DOC_PEERS = ("192.0.2.41", "198.51.100.23", "203.0.113.9")

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---- Shared service endpoints ----
#
# Nearly every live-stack test talks to one of two services: rag-api (TLS,
# :8000) and the dashboard BFF (:3002, its API under /api). They were reached
# through THIRTEEN different environment variables — RAG_API_URL, RAG_API,
# WSTG_URL, ST_URL, SCANS_URL, LAT_URL, CTRL_URL, CRED_URL, COV_URL, AGENT_API,
# BFF_BASE, BFF_URL, SMOKE_BASE, RECS_URL — and sixteen further files hardcoded
# the URL with no override at all. So "run the suite against another stack"
# required knowing every one of those names, and still missed a third of the
# files. The literal was never the real problem; the sprawl of names was.
#
# ONE variable per service. A file that already documents its own legacy name
# keeps honouring it FIRST (`os.environ.get("ST_URL") or RAG_API`), so no
# existing invocation breaks — but the DEFAULT now lives in exactly one place.
# Note ST_URL meant :8000 in one file and :3002 in another, which is precisely
# why the legacy names are resolved per-file and not folded in here.
RAG_API = os.environ.get("TEST_RAG_API", "https://localhost:8000").rstrip("/")
BFF = os.environ.get("TEST_BFF", "https://localhost:3002").rstrip("/")
BFF_API = f"{BFF}/api"


def load_service_module(file_path, module_name, service_dir):
    """Load a service module by path, with its SIBLING imports resolving correctly.

    The note at the top of this file explains why service directories are not on
    a shared sys.path. Loading by explicit file path avoids that — but only for
    the target module. `scan_recommender.py` does a BARE `from log_manager import
    ... LOGS_UI_HTML`, and both scan_recommender/ and autogen_agents/ ship a
    `log_manager`. If an earlier test in the session already imported the
    autogen_agents one, it sits in sys.modules and the bare import gets THAT
    copy — which has no LOGS_UI_HTML. The sys.path insert is powerless, because
    a cached module is never re-resolved.

    The symptom is a skip, not a failure: the loader reports "scan_recommender
    not importable in this env" and 75 real tests quietly do not run, while the
    same files pass 106/106 in isolation. An environment-shaped message for a
    test-ordering bug is the worst kind, because it looks like nothing is wrong.

    So: evict the colliding names, load, then put sys.modules back exactly as it
    was — this fixture must not become the thing that breaks somebody else.
    """
    import importlib.util

    siblings = {f[:-3] for f in os.listdir(service_dir) if f.endswith(".py")}
    saved = {n: sys.modules.pop(n) for n in list(siblings) if n in sys.modules}
    # PRESENCE on sys.path is not enough — POSITION decides. These test files
    # already insert their service dir at import time, but any test that later
    # does sys.path.insert(0, ".../autogen_agents") now sits in front of it, and
    # the bare `from log_manager import ...` resolves to the wrong copy. So put
    # this service dir at the front for the duration, and restore the path
    # exactly afterwards.
    saved_path = sys.path[:]
    sys.path.insert(0, service_dir)
    try:
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path[:] = saved_path
        for n in list(siblings):
            sys.modules.pop(n, None)
        sys.modules.update(saved)


def _render_loot(template: str) -> str:
    """Fill the fixture's {{PLACEHOLDERS}} with secret-SHAPED synthetic values.

    These are assembled here rather than committed because a literal 88-char
    Azure storage key in the repo trips GitHub's push protection — correctly.
    The resolution for a fixture is to stop storing secret-shaped strings, not to
    click "allow the secret": that is how a real leak gets waved through later.
    The values are still the right SHAPE, so the extractors are exercised exactly
    as they would be on real loot.
    """
    azure_key = ("QAbCdEf0123456789" * 6)[:86] + "=="          # 88 chars, b64-ish
    sas_sig = ("ZmljdGlvbmFsc2lnbmF0dXJl" * 2)[:44] + "%3D%3D"  # url-encoded tail
    gh_token = "ghp_" + ("FICTIONALtoken0123456789abcdefghij" * 2)[:36]
    return (template
            .replace("{{AZURE_ACCOUNT_KEY}}", azure_key)
            .replace("{{AZURE_SAS_SIG}}", sas_sig)
            .replace("{{GITHUB_TOKEN}}", gh_token))


@pytest.fixture
def loot_output() -> str:
    """Captured post-access enumeration output carrying SYNTHETIC loot: an AWS
    example key pair, Azure storage/SP/SAS values, an SSH private key + known_hosts,
    DB connection strings and sensitive documents. Drives the extractor -> fact ->
    rule controls. Nothing in it is a working credential."""
    raw = (FIXTURES_DIR / "pentest_loot_enumeration.txt").read_text(encoding="utf-8")
    return _render_loot(raw)


# ---- Skip budget ----
#
# A skip says "cannot run HERE". That is legitimate and most of this suite's
# skips are exactly that — no database, no running stack. But it makes a skip
# the perfect hiding place: a change that silently stops 75 tests from running
# looks identical to a machine without Postgres.
#
# That is not hypothetical. Two service directories each ship a `log_manager`,
# and once any test put autogen_agents/ on sys.path first, 75 scan_recommender
# tests began reporting "not importable in this env" — an environment-shaped
# message for a test-ordering bug. They pass 106/106 in isolation. The suite
# stayed green the whole time and the skip count simply grew.
#
# So: opt-in ceiling. Set PYTEST_SKIP_BUDGET=<n> (CI does) and the session FAILS
# if more tests skipped than that. Opt-in because the right number depends on
# what infrastructure is reachable, and because running a subset would otherwise
# trip it. Raise it only with a reason, the way the other ratchets here work.
_SKIP_BUDGET_ENV = "PYTEST_SKIP_BUDGET"


def pytest_sessionfinish(session, exitstatus):
    budget = os.environ.get(_SKIP_BUDGET_ENV)
    if not budget:
        return
    try:
        limit = int(budget)
    except ValueError:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    skipped = len(reporter.stats.get("skipped", []))
    if skipped <= limit:
        return
    reporter.write_line("")
    reporter.write_line(
        f"SKIP BUDGET EXCEEDED: {skipped} tests skipped, ceiling is {limit} "
        f"({_SKIP_BUDGET_ENV}).", red=True)
    reporter.write_line(
        "A skip means 'cannot run here'. If a change made tests stop running, "
        "fix that; if more infrastructure is genuinely absent, raise the ceiling "
        "with a reason. Run with -rs to see every reason.", red=True)
    # 1 is pytest's own "tests failed" status, so CI treats this like a failure.
    session.exitstatus = 1


# ---- Database Fixtures ----


@pytest.fixture
def mock_db_connection():
    """Mock database connection for testing without real DB."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=None)
    return mock_conn


@pytest.fixture
def db_dsn() -> str:
    """Return test database DSN from environment or default."""
    return os.getenv("TEST_DB_DSN", "postgresql://app:app@localhost:5432/test_scans")


# ---- Ollama/LLM Fixtures ----

@pytest.fixture
def mock_ollama_host() -> str:
    """Mock Ollama host for testing."""
    return "http://localhost:11434"


@pytest.fixture
def mock_embedding():
    """Mock embedding vector (768 dimensions)."""
    return [0.1] * 768


@pytest.fixture
def mock_ollama_response():
    """Mock successful Ollama API response."""
    return {
        "model": "nomic-embed-text",
        "embedding": [0.1] * 768,
        "response": "Test response from LLM"
    }


# ---- Playwright Fixtures ----

@pytest.fixture
def mock_playwright_page():
    """Mock Playwright page object."""
    page = MagicMock()
    page.url = "http://example.com"
    page.viewport_size = {"width": 1920, "height": 1080}
    return page


@pytest.fixture
def sample_screenshot_data() -> bytes:
    """Sample screenshot binary data."""
    # Simple 1x1 PNG
    return b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'


# ---- ExploitDB/SearchSploit Fixtures ----

@pytest.fixture
def sample_exploitdb_json(tmp_path: Path) -> Path:
    """Create sample SearchSploit JSON file."""
    import json

    json_data = {
        "RESULTS_EXPLOIT": [
            {
                "EDB-ID": "12345",
                "Title": "Test Exploit - RCE",
                "Platform": "linux",
                "Type": "remote",
                "Date": "2024-01-15",
                "Path": "exploits/linux/remote/12345.py"
            },
            {
                "EDB-ID": "12346",
                "Title": "Another Exploit - SQLi",
                "Platform": "windows",
                "Type": "webapps",
                "Date": "2024-02-20",
                "Path": "exploits/windows/webapps/12346.txt"
            }
        ],
        "RESULTS_SHELLCODE": []
    }

    json_file = tmp_path / "searchsploit.json"
    json_file.write_text(json.dumps(json_data))
    return json_file


@pytest.fixture
def sample_exploit_content() -> str:
    """Sample exploit file content."""
    return """#!/usr/bin/env python3
# Exploit Title: Sample RCE
# Author: Test Author
# CVE: CVE-2024-12345

import requests

def exploit(target):
    payload = "malicious_code_here"
    response = requests.post(f"{target}/vulnerable", data=payload)
    return response.text

if __name__ == "__main__":
    exploit("http://target.com")
"""


# ---- Network/HTTP Fixtures ----

@pytest.fixture
def mock_http_response():
    """Mock HTTP response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok"}
    mock_resp.text = "Success"
    return mock_resp


# ---- Security Check Fixtures ----

@pytest.fixture
def sample_security_headers() -> dict:
    """Sample security headers for testing."""
    return {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
    }


@pytest.fixture
def sample_cookies() -> list:
    """Sample cookies for security testing."""
    return [
        {
            "name": "session",
            "value": "abc123",
            "secure": True,
            "httpOnly": True,
            "sameSite": "Strict"
        },
        {
            "name": "tracking",
            "value": "xyz789",
            "secure": False,
            "httpOnly": False,
            "sameSite": "None"
        }
    ]


# ---- Test Environment Setup ----

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment variables."""
    os.environ["TESTING"] = "1"
    os.environ["OLLAMA_HOST"] = "http://localhost:11434"
    os.environ["EMBED_MODEL"] = "nomic-embed-text"
    os.environ["CHAT_MODEL"] = "mistral"
    yield
    # Cleanup
    os.environ.pop("TESTING", None)


# ---- Test DB Row Cleanup ----
# Tables touched by integration tests. Rows created during the test session
# (created_at >= session start) are removed on teardown so test runs don't
# leak data into the configured TEST_DB_DSN.
_CLEANUP_TABLES = (
    "tasks",
    "jobs",
    "followup_findings",
    "ports",
    "assets",
    "identities",
    "follow_up_items",
    "credential_findings",
    "recon_findings",
    "web_findings",
    "vulns",
)


# Rows a test can leave in a PRODUCTION table that the timestamp sweep above must
# NOT be widened to cover. `tool_selection_learned` and `pending_exploits` are
# live operational state — a concurrent real scan queuing an exploit during a
# pytest run would be inside the session window and would be deleted by a
# created_at-scoped DELETE. So these are cleaned by MARKER instead: only rows a
# test could have written, identified by a value no real row carries.
#
# Found 2026-09-21: 16 `__pytest_phase` rows in the learning table and an
# APPROVED `exploit/unix/misc/pytest_release` row in the live exploit queue.
_MARKER_CLEANUP = (
    ("tool_selection_learned", "phase = '__pytest_phase'"),
    ("pending_exploits", "exploit_id LIKE '%%pytest%%'"),
)


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_db_rows():
    """Delete rows inserted into the test DB during this pytest session.

    Captures a session-start timestamp; on teardown, connects to TEST_DB_DSN
    (or DB_DSN) and removes rows with created_at >= start from a defined list
    of test-affected tables. Silently skips if the DB is unreachable so unit
    tests that don't need a DB still run.
    """
    try:
        import psycopg2  # noqa: WPS433
    except ImportError:
        yield
        return

    dsn = os.environ.get("TEST_DB_DSN") or os.environ.get("DB_DSN")
    if not dsn:
        yield
        return

    start_ts = None
    try:
        with psycopg2.connect(dsn, connect_timeout=3) as conn, conn.cursor() as cur:
            cur.execute("SELECT now()")
            start_ts = cur.fetchone()[0]
    except Exception:
        # DB unreachable — nothing to clean.
        yield
        return

    yield

    try:
        with psycopg2.connect(dsn, connect_timeout=3) as conn:
            # marker-scoped first: these are live tables, so only rows carrying a
            # test marker are removed, never "everything since the session began"
            for table, where in _MARKER_CLEANUP:
                with conn.cursor() as cur:
                    try:
                        cur.execute(f"DELETE FROM {table} WHERE {where}")
                        conn.commit()
                    except Exception:
                        conn.rollback()
            for table in _CLEANUP_TABLES:
                with conn.cursor() as cur:
                    try:
                        cur.execute(
                            f"DELETE FROM {table} WHERE created_at >= %s",
                            (start_ts,),
                        )
                        conn.commit()
                    except Exception:
                        conn.rollback()
                        # Table missing or no created_at column — skip silently.
    except Exception:
        # DB went away mid-session; nothing more we can do.
        pass


# ---- Temporary Directory Fixtures ----

@pytest.fixture
def temp_screenshots_dir(tmp_path: Path) -> Path:
    """Create temporary directory for screenshots."""
    screenshots = tmp_path / "screenshots"
    screenshots.mkdir()
    return screenshots


@pytest.fixture
def temp_exploitdb_dir(tmp_path: Path) -> Path:
    """Create temporary ExploitDB directory structure."""
    exploitdb = tmp_path / "exploitdb"
    (exploitdb / "exploits" / "linux" / "remote").mkdir(parents=True)
    (exploitdb / "exploits" / "windows" / "webapps").mkdir(parents=True)
    return exploitdb
