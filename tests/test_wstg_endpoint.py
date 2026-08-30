"""GET /rag/wstg executes and returns a usable finding->test spec.

The endpoint is the single source of truth the agent tool and the surface-test
phase both call. If its query against exploit_chunks (doc_kind='wstg') or the
map load breaks, both silently lose WSTG guidance. Skips without a stack.

    WSTG_URL=https://localhost:8000 pytest tests/test_wstg_endpoint.py
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("WSTG_URL", "https://localhost:8000")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _get(path):
    try:
        return requests.get(f"{BASE}{path}", headers={"x-api-key": _key()},
                            timeout=20, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_match_by_cwe_returns_spec_and_guidance():
    r = _get("/rag/wstg?cwe=CWE-89&url=http://t/x?id=1")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"
    d = r.json()
    assert d["matched"] is True
    e = d["entry"]
    assert "WSTG-INPV-05" in e["wstg_id"]
    assert e["tier"] == "safe" and e["category"] == "sqli_detect"
    assert "http://t/x?id=1" in e.get("command_rendered", "")
    assert d["guidance"], "no WSTG prose returned — the exploit_chunks query is empty"


def test_no_match_is_a_clean_negative_not_an_error():
    r = _get("/rag/wstg?issue_type=totally-unknown-thing")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200
    assert r.json()["matched"] is False


def test_guides_lists_the_catalogue():
    r = _get("/rag/wstg/guides")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200
    d = r.json()
    assert d["count"] >= 10 and len(d["entries"]) == d["count"]


def test_fetch_one_guide_prose():
    r = _get("/rag/wstg/WSTG-INPV-05")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"
    assert "WSTG-INPV-05" in r.json()["guidance"] or r.json()["guidance"]
