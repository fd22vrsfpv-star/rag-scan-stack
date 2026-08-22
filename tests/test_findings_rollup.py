"""Virtual-host findings roll up into the overall findings search.

Run on demand:

    pytest tests/test_findings_rollup.py -v

WHY THIS EXISTS
---------------
`infrastructure_fingerprint` grouped vhost findings, but nothing consumed it:
`/findings/search` still counted one row per virtual host, so a single
server-level problem inflated `total` and every severity facet by however many
vhosts a machine had. A grouping key that no listing reads is the same mistake as
an artifact queue with no consumer.

The rollup is ADDITIVE on purpose. The default response is unchanged — one row
per vhost, because a tester triaging a specific host needs that row. What is new:

  * every finding carries `problem_id` and `affects_hosts`
  * `aggregations.distinct_problems` / `shared_problems` / `by_severity_deduped`
    answer "how many distinct problems", which is what a report headline means
  * `scope=shared|single` filters by whether a problem spans several vhosts
  * `collapse_problems=true` returns one row per problem

`scope` is derived from the data (`affects_hosts > 1`), not from a guess about
whether a finding is server- or app-level. That keeps it honest: a finding is
"shared" because it was actually observed on more than one host.

Skips cleanly when the stack is not running. Seeds into 203.0.113.53
(RFC 5737 TEST-NET-3) and removes it in a fixture teardown.
"""
import json
import os
import subprocess
import urllib.request
import ssl

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

TEST_IP = "203.0.113.53"
ASSET_A = "77777777-7777-7777-7777-777777777777"
ASSET_B = "88888888-8888-8888-8888-888888888888"


def _api_key():
    env = os.path.join(REPO, ".env")
    if not os.path.exists(env):
        return os.environ.get("API_KEY")
    with open(env, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("API_KEY")


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _get(query):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"https://localhost:3002/api/findings?ip={TEST_IP}&{query}"
    req = urllib.request.Request(url)
    key = _api_key()
    if key:
        req.add_header("x-api-key", key)
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


@pytest.fixture(scope="module")
def seeded():
    """Two vhosts on one IP: a shared problem at several paths, plus an app one."""
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres")
    try:
        _get("limit=1")
    except Exception as exc:                     # noqa: BLE001 - any transport failure
        pytest.skip(f"BFF not reachable: {type(exc).__name__}")

    _psql(f"""
        INSERT INTO assets (id, ip, hostname) VALUES
          ('{ASSET_A}','{TEST_IP}'::inet,'r1.rollup.test'),
          ('{ASSET_B}','{TEST_IP}'::inet,'r2.rollup.test')
        ON CONFLICT DO NOTHING;
        INSERT INTO web_findings (asset_id, url, source, issue_type, name, severity) VALUES
          ('{ASSET_A}','https://r1.rollup.test/','zap','hdr','Rollup Missing Header','high'),
          ('{ASSET_A}','https://r1.rollup.test/login','zap','hdr','Rollup Missing Header','high'),
          ('{ASSET_B}','https://r2.rollup.test/','zap','hdr','Rollup Missing Header','high'),
          ('{ASSET_B}','https://r2.rollup.test/home','zap','hdr','Rollup Missing Header','high'),
          ('{ASSET_A}','https://r1.rollup.test/q','zap','sqli','Rollup SQLi','high');
    """)
    yield
    _psql("DELETE FROM web_findings WHERE url LIKE '%rollup.test%';")
    _psql(f"DELETE FROM assets WHERE ip = '{TEST_IP}'::inet;")


def test_default_response_still_returns_one_row_per_vhost(seeded):
    """Additive by design — a tester triaging one host needs that host's row."""
    data = _get("limit=50")
    assert data["total"] == 5, f"expected the 5 seeded rows, got {data['total']}"


def test_counts_are_deduped_while_total_stays_row_based(seeded):
    """`total` drives pagination, so it must stay row-based.

    The honest headline is distinct_problems: 4 vhost rows of one problem plus
    one app finding is TWO problems, not five.
    """
    agg = _get("limit=50")["aggregations"]
    assert agg["distinct_problems"] == 2, agg
    assert agg["shared_problems"] == 1, agg


def test_deduped_severity_facet_counts_each_problem_once(seeded):
    """All five seeded rows are 'high'; the chart should show 2, not 5."""
    agg = _get("limit=50")["aggregations"]
    assert agg["by_severity_deduped"].get("high") == 2, agg["by_severity_deduped"]


def test_every_finding_carries_the_group_and_affected_count(seeded):
    findings = _get("limit=50")["findings"]
    shared = [f for f in findings if f["title"] == "Rollup Missing Header"]
    app = [f for f in findings if f["title"] == "Rollup SQLi"]
    assert len(shared) == 4 and len(app) == 1
    assert all(f["affects_hosts"] == 2 for f in shared), shared
    assert len({f["problem_id"] for f in shared}) == 1, "shared rows must share one group"
    assert app[0]["affects_hosts"] == 1
    assert app[0]["problem_id"] != shared[0]["problem_id"], \
        "an app-level finding must not join the infrastructure group"


def test_scope_shared_selects_only_multi_host_problems(seeded):
    data = _get("limit=50&scope=shared")
    assert data["total"] == 4, data["total"]
    assert all(f["affects_hosts"] > 1 for f in data["findings"])


def test_scope_single_selects_only_one_host_problems(seeded):
    data = _get("limit=50&scope=single")
    assert data["total"] == 1, data["total"]
    assert data["findings"][0]["title"] == "Rollup SQLi"


def test_scope_all_is_the_same_as_no_filter(seeded):
    assert _get("limit=50&scope=all")["total"] == _get("limit=50")["total"]


def test_unknown_scope_is_rejected(seeded):
    """A typo must not silently return everything."""
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get("limit=50&scope=nonsense")
    assert exc.value.code in (400, 422), exc.value.code


def test_collapse_returns_one_row_per_problem(seeded):
    findings = _get("limit=50&collapse_problems=true")["findings"]
    assert len(findings) == 2, [f["title"] for f in findings]
    titles = sorted(f["title"] for f in findings)
    assert titles == ["Rollup Missing Header", "Rollup SQLi"]


def test_collapse_keeps_ungroupable_rows_distinct(seeded):
    """The subtle one, and my first version of it was vacuous.

    Collapsing on problem_id alone would treat every ungroupable row (NULL) as
    ONE group and fold thousands of unrelated findings into a single result. The
    key must be COALESCE(problem_id, id).

    A first attempt asserted `len(findings) > 1`, which SURVIVED the sabotage:
    the NULLs folded to one row but the genuinely grouped problems remained, so
    the count was still greater than one. The assertion has to compare the
    collapsed row count against the number of groups the SQL claims exist —
    aggregations.distinct_problems is computed with the same COALESCE, so the
    two must agree exactly.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def fetch(query):
        req = urllib.request.Request(f"https://localhost:3002/api/findings?{query}")
        key = _api_key()
        if key:
            req.add_header("x-api-key", key)
        with urllib.request.urlopen(req, timeout=90, context=ctx) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    expected = fetch("limit=1")["aggregations"]["distinct_problems"]
    assert expected > 50, (
        f"only {expected} distinct problems overall — this deployment is too "
        "small for this test to discriminate")

    collapsed = fetch("limit=1000&collapse_problems=true")["findings"]
    # limit caps the page, so compare against whichever is smaller.
    assert len(collapsed) == min(expected, 1000), (
        f"collapse returned {len(collapsed)} row(s) but the aggregation counts "
        f"{expected} distinct problems — NULL problem_ids were folded together")


def test_problem_id_filter_selects_one_group(seeded):
    findings = _get("limit=50")["findings"]
    shared_group = next(f["problem_id"] for f in findings if f["affects_hosts"] > 1)
    data = _get(f"limit=50&problem_id={shared_group}")
    assert data["total"] == 4, data["total"]
    assert all(f["problem_id"] == shared_group for f in data["findings"])
