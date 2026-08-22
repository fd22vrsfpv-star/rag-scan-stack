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
  * `aggregations.distinct_problems` / `shared_problems` / `problems_by_severity`
    answer "how many distinct problems", which is what a report headline means
  * `problem_scope=shared|single` filters by whether a problem spans several vhosts
  * `collapse_problems=true` returns one row per problem

`problem_scope` is derived from the data (`affects_hosts > 1`), not from a guess about
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
    assert agg["problems_by_severity"].get("high") == 2, agg["problems_by_severity"]


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


def test_problem_scope_shared_selects_only_multi_host_problems(seeded):
    data = _get("limit=50&problem_scope=shared")
    assert data["total"] == 4, data["total"]
    assert all(f["affects_hosts"] > 1 for f in data["findings"])


def test_problem_scope_single_selects_only_one_host_problems(seeded):
    data = _get("limit=50&problem_scope=single")
    assert data["total"] == 1, data["total"]
    assert data["findings"][0]["title"] == "Rollup SQLi"


def test_problem_scope_all_is_the_same_as_no_filter(seeded):
    assert _get("limit=50&problem_scope=all")["total"] == _get("limit=50")["total"]


def test_unknown_problem_scope_is_rejected(seeded):
    """A typo must not silently return everything."""
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get("limit=50&problem_scope=nonsense")
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


# ── SARIF export: one result, many locations ─────────────────────────────────

def _sarif(extra=""):
    """Fetch SARIF from rag-api inside its own container (internal port is TLS)."""
    script = (
        "import os, json, ssl, urllib.request\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        f"req = urllib.request.Request('https://localhost:8000/export/sarif?source=zap&limit=5000&{extra}')\n"
        "req.add_header('x-api-key', os.environ.get('API_KEY',''))\n"
        "print(urllib.request.urlopen(req, timeout=90, context=ctx).read().decode())\n"
    )
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python", "-c", script],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except ValueError:
        return None


def _sarif_results_for(doc, marker):
    return [r for run in doc.get("runs", [])
            for r in run.get("results", [])
            if marker in json.dumps(r)]


@pytest.fixture(scope="module")
def sarif_seeded():
    """Three rows of one problem across two vhosts of one machine."""
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres")
    if _sarif("limit=1") is None:
        pytest.skip("rag-api /export/sarif not reachable")
    _psql("""
        INSERT INTO assets (id, ip, hostname) VALUES
          ('99999999-9999-9999-9999-999999999999','203.0.113.54'::inet,'s1.sarif.test'),
          ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','203.0.113.54'::inet,'s2.sarif.test')
        ON CONFLICT DO NOTHING;
        INSERT INTO web_findings (asset_id, url, source, issue_type, name, severity) VALUES
          ('99999999-9999-9999-9999-999999999999','https://s1.sarif.test/','zap','hdr','Sarif Missing Header','high'),
          ('99999999-9999-9999-9999-999999999999','https://s1.sarif.test/a','zap','hdr','Sarif Missing Header','high'),
          ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','https://s2.sarif.test/','zap','hdr','Sarif Missing Header','high');
    """)
    yield
    _psql("DELETE FROM web_findings WHERE url LIKE '%sarif.test%';")
    _psql("DELETE FROM assets WHERE ip = '203.0.113.54'::inet;")


def test_sarif_default_emits_one_result_per_row(sarif_seeded):
    doc = _sarif()
    assert doc is not None
    results = _sarif_results_for(doc, "sarif.test")
    assert len(results) == 3, f"expected the 3 seeded rows, got {len(results)}"
    assert all(len(r["locations"]) == 1 for r in results)


def test_sarif_collapse_emits_one_result_with_every_location(sarif_seeded):
    """SARIF represents "one problem, several places" natively.

    A result carries a LIST of locations, so a server-level problem should be one
    result with a location per affected virtual host — not three near-identical
    results a report consumer has to dedupe by hand.
    """
    doc = _sarif("collapse_problems=true")
    assert doc is not None
    results = _sarif_results_for(doc, "sarif.test")
    assert len(results) == 1, f"expected one collapsed result, got {len(results)}"
    locations = [l["physicalLocation"]["artifactLocation"]["uri"]
                 for l in results[0]["locations"]]
    assert sorted(locations) == [
        "https://s1.sarif.test/",
        "https://s1.sarif.test/a",
        "https://s2.sarif.test/",
    ], locations
    assert results[0]["properties"]["affects_locations"] == 3
    assert results[0]["properties"].get("problem_id"), \
        "a collapsed result should name the group it represents"


def test_sarif_collapse_does_not_merge_ungroupable_rows(sarif_seeded):
    """Same trap as the listing: keying on the fingerprint alone would fold every
    NULL-fingerprint row into a single result."""
    doc = _sarif("collapse_problems=true")
    plain = _sarif()
    assert doc is not None and plain is not None
    n_collapsed = sum(len(run.get("results", [])) for run in doc.get("runs", []))
    n_plain = sum(len(run.get("results", [])) for run in plain.get("runs", []))
    # Collapsing removes exactly the duplicate vhost rows, not the bulk.
    assert n_collapsed >= n_plain - 10, (
        f"collapse dropped {n_plain - n_collapsed} results — ungroupable rows "
        "were folded together")
    assert n_collapsed < n_plain, "collapse changed nothing"


# ── filtered vs global facets ────────────────────────────────────────────────

def _get_global(query):
    """Same call, without the TEST_IP filter _get() applies."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(f"https://localhost:3002/api/findings?{query}")
    key = _api_key()
    if key:
        req.add_header("x-api-key", key)
    with urllib.request.urlopen(req, timeout=90, context=ctx) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def test_filtered_facets_agree_with_the_filtered_total(seeded):
    """The bug this fixes: Dashboard charted a GLOBAL facet under a FILTERED total.

    by_severity ignores the query filters by design — the Findings Explorer needs
    every source chip to stay visible. But Dashboard.tsx passes engagement_id and
    charted by_severity, so with an engagement selected the card showed a
    filtered total (838) above a chart summing to the whole dataset (840).
    problems_by_severity is filtered, so it must reconcile.
    """
    data = _get("limit=1")
    agg = data["aggregations"]
    assert sum(agg["problems_by_severity"].values()) == agg["distinct_problems"], (
        "problems_by_severity does not sum to distinct_problems: "
        f"{agg['problems_by_severity']} vs {agg['distinct_problems']}")
    assert sum(agg["problems_by_source"].values()) == agg["distinct_problems"], (
        "problems_by_source does not sum to distinct_problems")


def test_global_facets_stay_global(seeded):
    """Deliberate, and must not regress.

    If by_source started respecting the filter, every source chip in the Findings
    Explorer would vanish as soon as a filter narrowed the set — the UI comments
    call this out explicitly.
    """
    narrow = _get("limit=1")               # filtered to TEST_IP
    wide = _get_global("limit=1")          # no ip filter
    assert narrow["aggregations"]["by_source"] == wide["aggregations"]["by_source"], (
        "by_source changed with the filter — it is meant to be global")
    assert narrow["total"] < wide["total"], "the ip filter did not narrow anything"


def test_filtered_source_facet_drops_sources_with_no_matching_rows(seeded):
    """The observable difference between the two facets."""
    data = _get("limit=1")
    agg = data["aggregations"]
    global_sources = set(agg["by_source"])
    filtered_sources = set(agg["problems_by_source"])
    assert filtered_sources <= global_sources, (
        f"filtered facet has sources the global one lacks: "
        f"{filtered_sources - global_sources}")
    assert filtered_sources != global_sources, (
        "filtered and global source facets are identical — this deployment "
        "cannot demonstrate the difference")

# ── crawl inventory vs findings ──────────────────────────────────────────────

def test_inventory_is_excluded_by_default(seeded):
    """A crawled URL is not a finding.

    746 of 779 rows were katana output — one row per discovered URL with no name
    and no issue_type — and they were counted as findings everywhere, which made
    the severity chart read "recon: 782" and left the vhost rollup nothing to
    group.
    """
    default = _get_global("limit=1")
    with_inv = _get_global("limit=1&include_inventory=true")
    assert with_inv["total"] > default["total"], (
        "include_inventory did not widen the result set — is the BFF forwarding "
        "the parameter? It silently drops unknown ones")
    assert with_inv["total"] - default["total"] > 100, (
        f"expected the bulk of the table to be inventory, got "
        f"{with_inv['total'] - default['total']} extra rows")


def test_inventory_sources_are_absent_from_the_default_facet(seeded):
    """Otherwise the UI renders a chip that returns nothing when clicked.

    by_source is deliberately global — it ignores the query filters so every
    source keeps a filter chip. But it must still respect the inventory rule, or
    a `katana` chip with 746 would select zero rows.
    """
    default = _get_global("limit=1")["aggregations"]["by_source"]
    with_inv = _get_global("limit=1&include_inventory=true")["aggregations"]["by_source"]
    inventory_only = set(with_inv) - set(default)
    assert inventory_only, (
        "no source is inventory-only — this deployment cannot demonstrate the rule")
    assert "katana" in inventory_only, f"expected katana, got {inventory_only}"


def test_record_kind_agrees_with_the_grouping_key(seeded):
    """Two features, one definition of "not a finding".

    infrastructure_fingerprint is NULL for exactly the rows record_kind calls
    inventory. If they drifted apart, a row could be groupable but not a
    finding, or vice versa.
    """
    mismatch = _psql(
        "SELECT count(*) FROM web_findings "
        "WHERE record_kind = 'inventory' AND infrastructure_fingerprint IS NOT NULL")
    assert mismatch == "0", f"{mismatch} inventory row(s) carry a grouping key"


def test_record_kind_is_generated_not_written(seeded):
    """A generated column cannot drift from the data it describes, and needs no
    writer changes — parse_katana was not touched."""
    expr = _psql(
        "SELECT generation_expression FROM information_schema.columns "
        "WHERE table_name = 'web_findings' AND column_name = 'record_kind'")
    assert expr, "record_kind is missing"
    assert "issue_type" in expr and "name" in expr, (
        f"record_kind is not derived from name/issue_type: {expr}")


def test_exports_still_see_the_crawl_surface(seeded):
    """The reason inventory is classified rather than moved or deleted.

    /export/burp and /export/har read web_findings BY URL to build the Burp
    sitemap and the HAR file — the tool's primary deliverable. Excluding
    inventory from the FINDINGS view must not shrink those.
    """
    script = (
        "import os, json, ssl, urllib.request\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False\n"
        "ctx.verify_mode = ssl.CERT_NONE\n"
        "r = urllib.request.Request('https://localhost:8000/export/har?limit=5000')\n"
        "r.add_header('x-api-key', os.environ.get('API_KEY',''))\n"
        "d = json.load(urllib.request.urlopen(r, timeout=120, context=ctx))\n"
        "print(len(d.get('log', {}).get('entries', [])))\n"
    )
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-api not reachable")
    if out.returncode != 0:
        pytest.skip(f"HAR export unavailable: {out.stderr[:120]}")
    entries = int(out.stdout.strip().splitlines()[-1])
    findings_only = _get_global("limit=1")["total"]
    assert entries > findings_only, (
        f"HAR has only {entries} entries but there are {findings_only} findings — "
        "the crawl surface was excluded from the export too, which breaks the "
        "Burp/ZAP import this tool exists for")
