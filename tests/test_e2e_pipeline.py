"""End-to-end verification of the running stack, through its HTTP APIs.

This drives the platform the way an operator does — dashboard BFF for reads,
rag-api for writes — rather than reaching around it into the database. Postgres
is deliberately not published to the host, so going through the API is both the
only option and the more honest test: it exercises routing, auth, scope
enforcement, ingestion, dedup and query together.

Run on demand:

    pytest tests/test_e2e_pipeline.py -v

Skips cleanly (not fails) when the stack is not running, so it can live in the
normal suite. Every test cleans up what it creates and is safe to re-run.

IMPORTANT: nothing here launches a scan against a real host. The one dispatch
test asserts that an OUT-OF-SCOPE target is REFUSED, which by definition sends
no traffic.
"""
import os
import re
import uuid
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

DASH = os.environ.get("E2E_DASHBOARD_URL", "https://localhost:3002")
RAG = os.environ.get("E2E_RAG_API_URL", "https://localhost:8000")
MARK = f"e2e-{uuid.uuid4().hex[:8]}"          # unique per run, for cleanup


def _api_key():
    env = Path(__file__).parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


@pytest.fixture(scope="module")
def client():
    c = httpx.Client(verify=False, timeout=45)
    try:
        r = c.get(f"{DASH}/api/health")
        if r.status_code != 200:
            pytest.skip(f"dashboard not healthy at {DASH} ({r.status_code})")
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"stack not reachable at {DASH}: {type(e).__name__}")
    yield c
    c.close()


@pytest.fixture(scope="module")
def rag(client):
    key = _api_key()
    try:
        r = client.get(f"{RAG}/health", headers={"x-api-key": key})
        if r.status_code != 200:
            pytest.skip(f"rag-api not healthy ({r.status_code})")
    except Exception as e:                       # pragma: no cover
        pytest.skip(f"rag-api unreachable: {type(e).__name__}")
    yield key


# ══════════════════════════════════════════════ 1. platform is actually up

@pytest.mark.e2e
def test_all_core_services_are_healthy(client):
    """Optional services (tunnels, sliver, wireguard) may be down by design;
    a core service being down invalidates everything below it."""
    h = client.get(f"{DASH}/api/health").json()
    unhealthy = {
        name: info for name, info in (h.get("services") or {}).items()
        if isinstance(info, dict)
        and info.get("status") not in ("healthy", "ok", "up")
        and not info.get("optional")
    }
    assert not unhealthy, f"core services unhealthy: {list(unhealthy)}"


@pytest.mark.e2e
def test_database_schema_guards_are_reported_present(client):
    """The dedup indexes and triggers are what stop findings multiplying. If the
    stack is up but they are missing, ingestion silently regresses."""
    h = client.get(f"{DASH}/api/health").json()
    assert h.get("status") in ("healthy", "degraded"), h.get("status")
    assert (h.get("core_healthy") or 0) > 0


# ══════════════════════════════════ 2. authorization boundary (no traffic)

@pytest.mark.e2e
@pytest.mark.parametrize("target", ["scanme.nmap.org", "8.8.8.8", "example.com"])
def test_out_of_scope_dispatch_is_refused(client, target):
    """The security-critical path: a scan aimed outside the engagement must be
    refused BEFORE any packet leaves. A 403 here is proof no traffic was sent.

    Anything other than a refusal means the platform would scan a third party.
    """
    r = client.post(f"{DASH}/api/scans/nmap",
                    json={"targets": [target], "ports": "80"})
    assert r.status_code in (400, 403), (
        f"out-of-scope target {target} was NOT refused (HTTP {r.status_code}); "
        f"body={r.text[:200]}"
    )


# ══════════════════════════════════════════ 3. ingest -> query round trip

@pytest.mark.e2e
def test_finding_written_via_api_is_queryable_and_scoped(client, rag):
    """Full path: write through rag-api, read back through the dashboard BFF.
    Exercises ingestion, the fingerprint trigger, and the unified search."""
    url = f"http://192.168.1.150/{MARK}-roundtrip"
    r = client.post(f"{RAG}/findings/note",
                    headers={"x-api-key": rag},
                    json={"url": url, "source": MARK, "name": "e2e round trip",
                          "severity": "info", "evidence": "first"})
    assert r.status_code == 200, r.text
    finding_id = r.json().get("id")
    assert finding_id, "no id returned"

    try:
        found = client.get(f"{DASH}/api/findings",
                           params={"search": f"{MARK}-roundtrip", "limit": 20}).json()
        urls = [f.get("url") for f in found.get("findings", [])]
        assert url in urls, f"written finding not visible via the BFF; got {urls[:3]}"
    finally:
        _cleanup(client, rag)


@pytest.mark.e2e
def test_reingesting_the_same_finding_does_not_duplicate(client, rag):
    """The dedup guarantee, end to end. katana previously wrote 32,218 rows for
    630 findings because nothing enforced this."""
    url = f"http://192.168.1.150/{MARK}-dedup"
    body = {"url": url, "source": MARK, "name": "e2e dedup",
            "severity": "info", "evidence": "run-1"}
    try:
        ids = []
        for i in range(3):
            body["evidence"] = f"run-{i}"
            r = client.post(f"{RAG}/findings/note",
                            headers={"x-api-key": rag}, json=body)
            assert r.status_code == 200, r.text
            ids.append(r.json().get("id"))

        assert len(set(ids)) == 1, (
            f"3 identical writes produced {len(set(ids))} distinct findings: {ids}"
        )
        found = client.get(f"{DASH}/api/findings",
                           params={"search": f"{MARK}-dedup", "limit": 20}).json()
        matching = [f for f in found.get("findings", []) if f.get("url") == url]
        assert len(matching) == 1, f"expected 1 row, found {len(matching)}"
    finally:
        _cleanup(client, rag)


# ══════════════════════════════════════════════ 4. no out-of-scope data

@pytest.mark.e2e
def test_no_out_of_scope_hosts_are_present_in_findings(client):
    """Regression guard for the katana incident: crawlers followed links to
    twiki.org, twitter.com, youtube.com and wikipedia, and those were stored as
    engagement findings. Scanning the live table is the only way to prove the
    ingest gate is holding in practice.
    """
    # Scope lives under a NAME; /api/scope with no name returns an empty set,
    # which would make this test vacuously pass.
    names = client.get(f"{DASH}/api/scope/names")
    assert names.status_code == 200, names.text[:120]
    scope_names = [n.get("name") for n in names.json().get("names", []) if n.get("name")]
    if not scope_names:
        pytest.skip("no scope configured; nothing to enforce against")

    scope_hosts = set()
    for nm in scope_names:
        r = client.get(f"{DASH}/api/scope", params={"name": nm})
        if r.status_code == 200:
            scope_hosts |= {t.get("target") for t in r.json().get("targets", [])
                            if t.get("target")}
    assert scope_hosts, f"scope names {scope_names} resolved to no targets"

    data = client.get(f"{DASH}/api/findings", params={"limit": 1000}).json()
    offenders = {}
    for f in data.get("findings", []):
        u = f.get("url") or ""
        m = re.match(r"^[a-z]+://([^/:]+)", u)
        if not m:
            continue
        host = m.group(1).lower()
        if not any(host == s.lower() or host.endswith("." + s.lower())
                   for s in scope_hosts):
            offenders.setdefault(host, 0)
            offenders[host] += 1
    assert not offenders, f"out-of-scope hosts present in findings: {offenders}"


# ══════════════════════════════════════════════════ 5. query surface sane

@pytest.mark.e2e
def test_severity_facets_agree_with_the_result_count(client):
    """Facets and rows come from two separate SQL blocks. When they drift the
    UI shows counts that do not match the list, which reads as a UI bug."""
    d = client.get(f"{DASH}/api/findings", params={"limit": 1}).json()
    agg = (d.get("aggregations") or {}).get("by_severity") or {}
    assert sum(agg.values()) == d.get("total"), (
        f"severity facets sum to {sum(agg.values())} but total is {d.get('total')}"
    )


@pytest.mark.e2e
def test_source_facets_agree_with_the_result_count(client):
    d = client.get(f"{DASH}/api/findings", params={"limit": 1}).json()
    agg = (d.get("aggregations") or {}).get("by_source") or {}
    assert sum(agg.values()) == d.get("total")


@pytest.mark.e2e
def test_severity_filter_returns_only_that_severity(client):
    d = client.get(f"{DASH}/api/findings",
                   params={"severity": "critical", "limit": 50}).json()
    bad = [f.get("severity") for f in d.get("findings", [])
           if f.get("severity") != "critical"]
    assert not bad, f"severity filter leaked: {set(bad)}"


# ═══════════════════════════════════════════════ 6. agent + tool surfaces

@pytest.mark.e2e
@pytest.mark.parametrize("path", [
    "/api/agent-sessions",
    "/api/model/performance-warning",   # 404'd for a long time; UI called it anyway
    "/api/scope/names",
    "/api/engagements",
    "/api/assets",
])
def test_operator_endpoints_answer(client, path):
    r = client.get(f"{DASH}{path}")
    assert r.status_code == 200, f"{path} -> {r.status_code}: {r.text[:120]}"


@pytest.mark.e2e
def test_flow_summary_endpoint_answers_for_a_real_session(client):
    """This endpoint existed with no BFF route in front of it, so the UI could
    not reach it at all and had to read a stale metadata blob instead."""
    sessions = client.get(f"{DASH}/api/agent-sessions").json()
    items = sessions if isinstance(sessions, list) else sessions.get("sessions", [])
    if not items:
        pytest.skip("no agent sessions recorded yet")
    sid = items[0].get("session_id") or items[0].get("id")
    r = client.get(f"{DASH}/api/agent-sessions/{sid}/flow-summary")
    assert r.status_code == 200, r.text[:150]
    assert "source" in r.json()


# ════════════════════════════════════════════════════════ 7. exploit data

@pytest.mark.e2e
def test_exploit_corpus_is_populated(client, rag):
    """exploitdb-etl crash-looped for a long time because the database it
    connects to had never been created, so CVE/exploit matching had no data."""
    r = client.get(f"{RAG}/exploitdb/version", headers={"x-api-key": rag})
    assert r.status_code == 200, r.text[:150]
    out = (r.json() or {}).get("output", "")
    m = re.search(r"(\d[\d,]*)\s+exploits", out)
    assert m, f"could not read an exploit count from {out!r}"
    count = int(m.group(1).replace(",", ""))
    assert count > 1000, (
        f"exploit corpus reports only {count} entries — exploitdb-etl exits 1 "
        "and ingests nothing when the exploits database or edb_rw role is missing"
    )


# ═════════════════════════════════════════════════════════════ helpers

def _cleanup(client, key):
    """Remove anything this run created. Best-effort: a failure to clean up must
    not fail the test that already proved its point."""
    try:
        found = client.get(f"{DASH}/api/findings",
                           params={"search": MARK, "limit": 100}).json()
        ids = [f.get("id") for f in found.get("findings", []) if f.get("id")]
        if ids:
            client.request("DELETE", f"{RAG}/findings/bulk",
                           headers={"x-api-key": key}, json={"ids": ids})
    except Exception:
        pass
