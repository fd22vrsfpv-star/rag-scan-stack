import os
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
#MIGR_FILE = REPO_ROOT / "db_init" / "002_jobs.sql"

API_KEY = os.environ.get("API_KEY", "changeme")

def load_api_module():
    # Ensure DB_DSN is set before import
    os.environ.setdefault("DB_DSN", os.environ.get("TEST_DB_DSN", "postgresql://app:app@127.0.0.1:5432/scans"))
    spec = importlib.util.spec_from_file_location("rag_api_module", str(API_FILE))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rag_api_module"] = mod
    spec.loader.exec_module(mod)  # type: ignore
    return mod

def _connect(dsn: str):
    return psycopg2.connect(dsn)

def _apply_migration(dsn: str):
    with _connect(dsn) as conn, conn.cursor() as cur:
        if MIGR_FILE.exists():
            sql = MIGR_FILE.read_text()
            cur.execute(sql)
            conn.commit()

@pytest.fixture(scope="session")
def db_dsn():
    return os.environ.get("TEST_DB_DSN", os.environ.get("DB_DSN", "postgresql://app:app@127.0.0.1:5432/scans"))

@pytest.fixture(scope="session")
def db_or_skip(db_dsn):
    try:
        _apply_migration(db_dsn)
        return db_dsn
    except Exception as e:
        pytest.skip(f"Skipping DB-backed tests: cannot connect/apply migration to {db_dsn}: {e!r}")

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
    class _E(Exception): pass
    def _raise(*a, **kw): 
        import requests as _r
        raise _r.exceptions.ConnectionError("unreachable")
    monkeypatch.setattr(api_app, "requests", types.SimpleNamespace(post=_raise))
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
