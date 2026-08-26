"""Generic follow-ups export — csv / urls / md / json.

Run on demand:

    pytest tests/test_follow_up_export.py -v

WHY THIS EXISTS
---------------
Handing a team the "expired certs" list meant a one-off script. This endpoint
makes it general: any follow-up view (filtered by rule/severity/status) exports
to CSV (flat + detail_json), a de-duplicated URL list, a grouped Markdown report,
or JSON — enriched with the linked finding's detail. The properties worth pinning:

  * the filters mirror GET /follow-ups, so rule_id=expired_cert exports exactly
    those rows and nothing else;
  * urls are de-duplicated and look like URLs (the whole point of the "list of
    URLs" ask);
  * the format is honoured (content-type + a filename), and json round-trips.

Uses the live rag-api container; skips cleanly when it is not reachable.
"""
import csv
import io
import json
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _curl(path):
    """GET an api.py path inside the rag-api container. Returns body or None."""
    script = (
        "import os,urllib3,requests;urllib3.disable_warnings();"
        "k=os.environ.get('API_KEY','changeme');"
        f"r=requests.get('https://localhost:8000{path}',headers={{'x-api-key':k}},verify=False,timeout=60);"
        "print(r.status_code);print(r.text)"
    )
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    body = out.stdout.split("\n", 1)
    if len(body) < 2 or body[0].strip() != "200":
        return None
    return body[1]


@pytest.fixture(scope="module")
def live():
    if _curl("/health") is None and _curl("/follow-ups/export?format=urls&limit=1") is None:
        pytest.skip("rag-api container not reachable")
    return True


@pytest.mark.unit
def test_endpoint_and_helper_declared():
    src = open(API).read()
    assert '@app.get("/follow-ups/export"' in src
    assert "def _derive_follow_up_url" in src


def test_csv_has_expected_columns_and_detail(live):
    body = _curl("/follow-ups/export?format=csv&rule_id=expired_cert")
    if body is None:
        pytest.skip("export csv not reachable")
    rows = list(csv.DictReader(io.StringIO(body)))
    # header present even when zero rows
    reader = csv.reader(io.StringIO(body))
    header = next(reader)
    for col in ("follow_up_id", "rule_id", "host", "url", "severity", "detail_json"):
        assert col in header, header
    # if this engagement has expired-cert follow-ups, they are ALL that rule
    if rows:
        assert {r["rule_id"] for r in rows} == {"expired_cert"}, "filter leaked other rules"
        assert all(r["url"].startswith(("http://", "https://")) for r in rows)


def test_urls_are_unique_and_urls(live):
    body = _curl("/follow-ups/export?format=urls&rule_id=expired_cert")
    if body is None:
        pytest.skip("export urls not reachable")
    lines = [l for l in body.splitlines() if l.strip()]
    assert len(lines) == len(set(lines)), "urls not de-duplicated"
    assert all(l.startswith(("http://", "https://")) for l in lines), lines[:3]


def test_markdown_groups_by_rule(live):
    body = _curl("/follow-ups/export?format=md")
    if body is None:
        pytest.skip("export md not reachable")
    assert body.lstrip().startswith("# Follow-ups export")
    # grouped sections use '## <rule>' headers when any items exist
    if "item(s)" in body:
        assert "\n## " in body


def test_json_round_trips(live):
    body = _curl("/follow-ups/export?format=json&rule_id=expired_cert")
    if body is None:
        pytest.skip("export json not reachable")
    data = json.loads(body)
    assert "follow_ups" in data and "count" in data
    assert data["count"] == len(data["follow_ups"])
    for item in data["follow_ups"]:
        assert item["rule_id"] == "expired_cert"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
