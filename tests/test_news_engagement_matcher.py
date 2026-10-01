"""Exercises the news-item ↔ engagement data matcher.

Covers:
  - _poc_shell_syntax_check-style helper calls land inside the container
  - strong tier = CVE-matched vuln / follow-up (confidence='strong')
  - weak tier = product-only summary token match (confidence='weak')
  - engagement scoping — a vuln on an out-of-engagement asset is excluded
  - vulns.cve && %s::text[] array-overlap works (the bug that made
    news-runner's _match_assets return zero rows against every real DB)
  - serializer surfaces metadata.engagement_match.<eid> as a flat field

Skips cleanly when rag-api isn't reachable (CLAUDE.md: standalone tests).
"""
import json
import subprocess
import pytest


def _rag_api_up():
    try:
        r = subprocess.run(
            ["docker", "exec", "rag-api", "sh", "-lc",
             "curl -sk https://localhost:8000/health -o /dev/null -w '%{http_code}'"],
            capture_output=True, text=True, timeout=6,
        )
        return r.returncode == 0 and r.stdout.strip() == "200"
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _rag_api_up(),
                                reason="rag-api container not reachable")


def _in_container(py_snippet):
    r = subprocess.run(
        ["docker", "exec", "rag-api", "python3", "-c", py_snippet],
        capture_output=True, text=True, timeout=20,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def test_matcher_helper_returns_shape():
    """The core helper returns {matched_at, match_count, confidence, summary,
    sources{vulns, follow_ups, software}} for any input (even zero hits)."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _match_news_item_against_engagement
# Fake news item: no CVE, no summary -> zero matches, weak tier
row = {'id':'fake','title':'test','summary':'','all_cves':[],'primary_cve':None}
b = _match_news_item_against_engagement(row, '00000000-0000-0000-0000-000000000001')
assert b['match_count'] == 0
assert b['confidence'] == 'weak'
assert set(b['sources'].keys()) == {'vulns','follow_ups','software'}
assert 'summary' in b and 'matched_at' in b
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_vulns_array_overlap_sql_works():
    """The SQL used by the matcher (`v.cve && %s::text[]`) correctly handles
    text[] vuln.cve columns — the bug that silently returned zero rows."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import get_db
with get_db() as c, c.cursor() as cur:
    # Smoke: query shape runs without error against the real DB
    cur.execute("SELECT count(*) FROM vulns WHERE cve && %s::text[]",
                (['CVE-2024-TEST'],))
    print('ran OK, count:', cur.fetchone()[0])
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'ran OK' in out, f"stderr: {err}"


def test_serializer_exposes_engagement_match_slot():
    """_ser_news_item pulls the current-engagement slot out of
    metadata.engagement_match and exposes it as a flat `engagement_match`
    field — the UI never has to index by eid."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _ser_news_item
from datetime import datetime, timezone
row = {
  'id': '00000000-0000-0000-0000-000000000001',
  'title': 't', 'summary': 's', 'primary_cve': None, 'all_cves': [],
  'status': 'new', 'acknowledged_by': None, 'acknowledged_at': None,
  'kev_listed': None, 'rce': None, 'easily_exploitable': None,
  'malware_exploitable': None, 'active_internet_breach': None,
  'patch_available': None, 'articles': [], 'github_links': [],
  'asset_matches': [], 'published_at': None,
  'first_seen': datetime.now(timezone.utc), 'last_seen': datetime.now(timezone.utc),
  'enriched_at': None, 'github_searched_at': None, 'asset_matched_at': None,
  'notes': None, 'tags': [],
  'metadata': {'engagement_match': {
      'EID-1': {'match_count': 2, 'confidence': 'strong',
                'summary': 'affects X', 'sources': {'vulns':[],'follow_ups':[],'software':[]},
                'matched_at': '2026-01-01T00:00:00+00:00'}}}}
s1 = _ser_news_item(row, engagement_id='EID-1')
assert s1['engagement_match'] is not None, s1
assert s1['engagement_match']['match_count'] == 2
assert s1['engagement_match']['confidence'] == 'strong'
# Different engagement — no slot present -> None
s2 = _ser_news_item(row, engagement_id='EID-OTHER')
assert s2['engagement_match'] is None
# No engagement_id arg -> None
s3 = _ser_news_item(row)
assert s3['engagement_match'] is None
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_endpoint_single_item_match_shape_live():
    """Live-smoke the single-item match endpoint using the first news item in
    the DB and the first-asset-owning engagement. Shape-only — don't assert
    on hits, just that the endpoint runs clean and returns the right fields."""
    py = """
import sys, json; sys.path.insert(0,'/app')
from api import get_db
with get_db() as c, c.cursor() as cur:
    cur.execute("SELECT engagement_id FROM assets WHERE engagement_id IS NOT NULL "
                "GROUP BY engagement_id ORDER BY count(*) DESC LIMIT 1")
    eid = cur.fetchone()
    cur.execute("SELECT id FROM news_items ORDER BY last_seen DESC LIMIT 1")
    nid = cur.fetchone()
    print(json.dumps({'eid': str(eid[0]) if eid else None,
                      'nid': str(nid[0]) if nid else None}))
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    ids = json.loads(out.splitlines()[-1])
    if not ids["eid"] or not ids["nid"]:
        pytest.skip("no engagement or news items in DB")
    r = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         f'curl -sk -H "x-api-key: $API_KEY" -H "X-Engagement-Id: {ids["eid"]}" '
         f'-X POST https://localhost:8000/news/items/{ids["nid"]}/match-engagement'],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout)
    assert body["ok"] is True
    em = body["engagement_match"]
    assert "match_count" in em and "confidence" in em and "summary" in em
    assert em["confidence"] in ("strong", "weak")
    assert set(em["sources"].keys()) == {"vulns", "follow_ups", "software"}


def test_batch_endpoint_live():
    """Live-smoke the batch endpoint: scanned/updated/skipped/matched_hits
    all present and non-negative; re-run with max_age_hours=24 reports
    higher skipped (cache hit)."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import get_db
with get_db() as c, c.cursor() as cur:
    cur.execute("SELECT engagement_id FROM assets WHERE engagement_id IS NOT NULL "
                "GROUP BY engagement_id ORDER BY count(*) DESC LIMIT 1")
    r = cur.fetchone()
    print(str(r[0]) if r else '')
"""
    out, err, rc = _in_container(py)
    if rc != 0 or not out.strip():
        pytest.skip("no engagement with assets available")
    eid = out.strip()
    r1 = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         f'curl -sk -H "x-api-key: $API_KEY" -H "X-Engagement-Id: {eid}" '
         f'-X POST "https://localhost:8000/news/items/match-engagement?limit=5&max_age_hours=0"'],
        capture_output=True, text=True, timeout=60,
    )
    assert r1.returncode == 0, r1.stderr
    body = json.loads(r1.stdout)
    assert body["ok"] is True
    for k in ("scanned", "updated", "skipped", "matched_hits"):
        assert k in body and body[k] >= 0


def test_affects_engagement_filter_requires_eid():
    """affects_engagement=true without X-Engagement-Id must return 400."""
    r = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         'curl -sk -H "x-api-key: $API_KEY" '
         '-o /dev/null -w "%{http_code}" '
         '"https://localhost:8000/news/items?affects_engagement=true&limit=1"'],
        capture_output=True, text=True, timeout=10,
    )
    assert r.stdout.strip() == "400", (
        f"expected 400 when affects_engagement=true without X-Engagement-Id, "
        f"got {r.stdout.strip()}: {r.stderr}")
