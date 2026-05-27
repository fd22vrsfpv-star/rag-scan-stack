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
