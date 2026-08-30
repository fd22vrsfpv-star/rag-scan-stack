import os
import re
import sys
import time
import types
import pathlib
import importlib.util

import psycopg2
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
API_FILE = REPO_ROOT / "app" / "rag-api" / "api.py"

API_KEY = os.environ.get("API_KEY", "changeme")


def _redact(dsn: str) -> str:
    """Never put a live password in test output — skip messages reach CI logs."""
    return re.sub(r"://([^:/@]+):[^@]*@", r"://\1:***@", dsn or "")

def load_api_module():
    # Ensure DB_DSN is set before import
    os.environ.setdefault("DB_DSN", os.environ.get("TEST_DB_DSN", "postgresql://app:app@127.0.0.1:5433/scans"))
    # api.py imports its siblings flat (`import vault_client`), the way it does
    # inside its container where /app is the working directory. Loading it by
    # path without that directory on sys.path fails with ModuleNotFoundError —
    # which the old MIGR_FILE NameError hid, because the fixture never got far
    # enough to try.
    api_dir = str(API_FILE.parent)
    if api_dir not in sys.path:
        sys.path.insert(0, api_dir)
    spec = importlib.util.spec_from_file_location("rag_api_module", str(API_FILE))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rag_api_module"] = mod
    spec.loader.exec_module(mod)  # type: ignore
    return mod

def _connect(dsn: str):
    return psycopg2.connect(dsn)

def _require_schema(dsn: str):
    """Confirm the tables exist. Do NOT try to create them.

    This used to read db_init/002_jobs.sql, whose definition was commented out
    at the top of this file while the two uses of MIGR_FILE below it stayed —
    so the fixture raised NameError, and the `except Exception` around it
    reported that as "cannot connect/apply migration". The tests looked like
    they were waiting for a database when they were simply broken; the file
    itself is long gone, and jobs/tasks are created by ensure_all_tables.sql.
    """
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("""SELECT count(*) FROM information_schema.tables
                        WHERE table_schema = 'public'
                          AND table_name IN ('jobs', 'tasks')""")
        found = cur.fetchone()[0]
    if found != 2:
        raise RuntimeError(
            f"jobs/tasks missing (found {found} of 2) — run scripts/ensure_db_schema.sh")

@pytest.fixture(scope="session")
def db_dsn():
    return os.environ.get("TEST_DB_DSN", os.environ.get("DB_DSN", "postgresql://app:app@127.0.0.1:5433/scans"))

@pytest.fixture(scope="session")
def db_or_skip(db_dsn):
    try:
        _require_schema(db_dsn)
        return db_dsn
    except Exception as e:
        pytest.skip(f"no database at {_redact(db_dsn)}: {type(e).__name__}: {e}")

@pytest.fixture()
def api_app(db_or_skip, monkeypatch):
    # Ensure API sees our DSN
    monkeypatch.setenv("DB_DSN", db_or_skip)
    mod = load_api_module()
    # Clean out jobs/tasks before each test
    with psycopg2.connect(db_or_skip) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM tasks")
        cur.execute("DELETE FROM jobs")
        conn.commit()
    return mod

@pytest.fixture()
def client(api_app):
    return TestClient(api_app.app)

def auth_headers():
    return {"x-api-key": API_KEY}

class FakeRespOK:
    status_code = 200
    headers = {"content-type": "application/json"}
    def raise_for_status(self): return None
    def json(self): return {"ok": True, "stats": {"nmap": 1}}

class FakeRespFail:
    status_code = 200
    headers = {"content-type": "application/json"}
    def raise_for_status(self): return None
    def json(self): return {"ok": False, "error": "simulated failure"}

def test_create_job_and_dedup(client, api_app):
    body = {"type": "masscan-nmap", "params": {"note": "t1"}, "idempotency_key": "abc123"}
    r = client.post("/jobs", json=body, headers=auth_headers())
    assert r.status_code == 200, r.text
    j1 = r.json()
    assert "id" in j1 and j1["status"] == "queued"
    # Duplicate
    r2 = client.post("/jobs", json=body, headers=auth_headers())
    assert r2.status_code == 200, r2.text
    j2 = r2.json()
    assert j2.get("dedup") is True
    assert j2["id"] == j1["id"]

def test_job_lifecycle_success(client, api_app, monkeypatch, db_or_skip):
    # Mock scanner response OK
    monkeypatch.setattr(api_app, "requests", types.SimpleNamespace(post=lambda *a, **kw: FakeRespOK()))
    # Create job
    r = client.post("/jobs", json={"type":"masscan-nmap", "params":{}}, headers=auth_headers())
    job_id = r.json()["id"]
    # Trigger job with lifecycle
    r2 = client.post(f"/jobs/nmap-from-masscan?job_id={job_id}", headers=auth_headers())
    assert r2.status_code == 200, r2.text
    payload = r2.json()
    assert payload.get("ok") is True
    # Verify job and task status
    j = client.get(f"/jobs/{job_id}", headers=auth_headers()).json()
    assert j["status"] == "finished"
    assert j["finished_tasks"] == 1
    t = client.get(f"/jobs/{job_id}/tasks", headers=auth_headers()).json()
    assert t["count"] == 1
    assert t["items"][0]["type"] == "pipeline"
    assert t["items"][0]["status"] == "finished"

def test_job_lifecycle_scanner_unavailable(client, api_app, monkeypatch):
    # Mock scanner raising connection error
    import requests as _r
    def _raise(*a, **kw):
        raise _r.exceptions.ConnectionError("unreachable")
    # The handler catches `requests.RequestException`, so a stand-in with only
    # `post` makes the except clause itself raise AttributeError and the test
    # fails for a reason that has nothing to do with the behaviour under test.
    monkeypatch.setattr(api_app, "requests", types.SimpleNamespace(
        post=_raise, RequestException=_r.RequestException, exceptions=_r.exceptions))
    # Create job
    r = client.post("/jobs", json={"type":"masscan-nmap"}, headers=auth_headers())
    job_id = r.json()["id"]
    # Trigger job
    r2 = client.post(f"/jobs/nmap-from-masscan?job_id={job_id}", headers=auth_headers())
    assert r2.status_code == 502
    # Inspect job
    j = client.get(f"/jobs/{job_id}", headers=auth_headers()).json()
    assert j["status"] == "failed"
    t = client.get(f"/jobs/{job_id}/tasks", headers=auth_headers()).json()
    assert t["count"] == 1
    assert t["items"][0]["status"] == "failed"
