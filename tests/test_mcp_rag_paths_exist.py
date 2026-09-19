"""Every rag-api path an MCP tool calls must resolve to a declared rag-api route.

Run on demand:

    pytest tests/test_mcp_rag_paths_exist.py -v

WHY THIS EXISTS
---------------
MCP tools call rag-api by URL. burp `search_findings` and zap `search_zap_findings`
POSTed to `/findings` (no such route — it is `/findings/search`) and zap
`import_zap_xml_report` posted to `/ingest/generic` (no such route — it is
`/ingest/zap`), so those tools silently returned {"error":"Not Found"}. Same
class as the BFF upstream-path guard: a URL that no service declares is a dead
tool that looks healthy from outside.

SABOTAGE PROOF
--------------
Point an MCP tool at a bogus `RAG_API_URL}/nope` and this fails, naming it.
"""
import os
import re
import glob

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")
MCP_GLOB = os.path.join(REPO, "mcp", "*.py")

# Static-prefix rag-api paths that legitimately vary at runtime beyond what this
# static check can resolve — declare with a reason (keep this tiny).
KNOWN_DYNAMIC: dict = {}


def _norm(path):
    """Normalise a route/reference to a tuple of segments, with '{...}' -> '*'."""
    path = path.split("?")[0].rstrip("/")
    segs = [s for s in path.split("/") if s != ""]
    return tuple("*" if s.startswith("{") else s for s in segs)


def _routes():
    """All rag-api routes: @app.* in api.py PLUS routes on included APIRouters
    (with their prefix), across every app/rag-api/**/*.py — otherwise
    router-mounted paths like /metrics/* read as 'dead'."""
    ragdir = os.path.join(REPO, "app", "rag-api")
    if not os.path.isdir(ragdir):
        pytest.skip("app/rag-api not present")
    routes = set()
    for f in glob.glob(os.path.join(ragdir, "**", "*.py"), recursive=True):
        src = open(f, encoding="utf-8", errors="ignore").read()
        # a file may define an APIRouter with a prefix; routes on it are relative
        pm = re.search(r'APIRouter\([^)]*prefix\s*=\s*"([^"]*)"', src)
        prefix = pm.group(1) if pm else ""
        for m in re.finditer(r'@\w+\.(?:get|post|put|delete|patch)\("(/[^"]*)"', src):
            path = m.group(1)
            routes.add(_norm(path))            # as written (covers @app.*)
            if prefix:
                routes.add(_norm(prefix + path))  # prefixed (covers @router.*)
    return routes


def _mcp_refs():
    refs = []  # (file, raw_path, norm)
    for f in glob.glob(MCP_GLOB):
        base = os.path.basename(f)
        text = open(f, encoding="utf-8", errors="ignore").read()
        # f-string paths: f"{RAG_API_URL}/foo/{bar}"  -> capture up to the quote
        for m in re.finditer(r'RAG_API_URL\}(/[^"\']*)', text):
            raw = m.group(1)
            # cut at the first thing that isn't part of a URL path/param
            raw = re.split(r'["\'\s]', raw)[0]
            refs.append((base, raw, _norm(raw)))
    return refs


def _matches(ref, routes):
    if ref in routes:
        return True
    # wildcard match: same length, each segment equal or one side is '*'
    for r in routes:
        if len(r) != len(ref):
            continue
        if all(a == b or a == "*" or b == "*" for a, b in zip(r, ref)):
            return True
    return False


def test_every_mcp_rag_path_resolves():
    routes = _routes()
    refs = _mcp_refs()
    assert refs, "no RAG_API_URL references found in mcp/*.py — matcher broken?"
    dead = []
    for base, raw, norm in refs:
        if raw in KNOWN_DYNAMIC:
            continue
        if not _matches(norm, routes):
            dead.append(f"{base}: {raw}")
    assert not dead, (
        "MCP tools call rag-api paths that no route declares (dead tools):\n  "
        + "\n  ".join(sorted(set(dead))))
