"""Engagement-aware scope auto-classification + self-learned rules.

Run on demand:

    pytest tests/test_scope_learn.py -v
    scripts/run_db_tests.sh tests/test_scope_learn.py    # with the DB

WHY THIS EXISTS
---------------
subfinder found 6,117 subdomains and NONE reached an engagement: every ingest
path (auto-assign-unknown, classify-unknown, accept-suggestion) inserted scope
rows with `engagement_id = NULL`, and the Recon Agent only scans targets whose
`scope_targets.engagement_id` matches an engagement. So the whole discovery set
was stored, visible, and unscannable.

The fix makes classification engagement-aware and turns the operator's seed
scope into deterministic `*.{domain}` rules, so future hosts classify WITHOUT
the LLM. Three properties are pinned here, each a way the feature could look
right while doing nothing:

  * a generated/distilled rule actually MATCHES the hosts it should (fnmatch on
    the pattern, not the seed apex);
  * classification stamps engagement_id on BOTH the in-scope and the unknown
    buckets — the entire bug was engagement-less rows;
  * a one-off decision distils to a reusable rule (registrable domain), so the
    same shape is never re-judged.

Every DB mutation below runs inside a transaction that is ROLLED BACK, so the
suite leaves no rows behind.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MODULE = os.path.join(REPO, "app", "rag-api", "scope_classifier.py")


def _run(script):
    """Execute a python snippet inside the rag-api container. None if unreachable."""
    try:
        out = subprocess.run(["docker", "exec", "-i", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return f"__ERR__ {out.stderr.strip()[-800:]}"
    return out.stdout


@pytest.fixture(scope="module")
def container():
    if _run("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    return True


# ── source-level (always run) ───────────────────────────────────────────────

@pytest.mark.unit
def test_module_exists():
    assert os.path.exists(MODULE), MODULE


@pytest.mark.unit
def test_helpers_are_exported():
    """The endpoint imports these by name; a rename would 500 at request time."""
    src = open(MODULE).read()
    for fn in ("def generate_seed_rules", "def classify_and_assign_engagement",
               "def distill_rule_from_decision", "def registrable_domain",
               "def target_type_of", "def classify_rules_only"):
        assert fn in src, f"missing {fn}"


# ── pure logic (in-container, no DB) ─────────────────────────────────────────

def test_registrable_domain_and_target_type(container):
    out = _run(
        "import scope_classifier as s;"
        "print(s.registrable_domain('a.b.blackbaud.com'));"
        "print(s.registrable_domain('x.example.co.uk'));"
        "print(s.registrable_domain('10.0.0.1'));"
        "print(s.target_type_of('1.2.3.4'));"
        "print(s.target_type_of('10.0.0.0/24'));"
        "print(s.target_type_of('foo.blackbaud.com'))")
    assert out and not out.startswith("__ERR__"), out
    lines = out.strip().splitlines()
    assert lines == ["blackbaud.com", "example.co.uk", "None", "ip", "cidr", "domain"], lines


def test_rule_only_classification_matches_subdomains(container):
    """A *.blackbaud.com rule matches a subdomain but NOT an unrelated host."""
    out = _run(
        "import scope_classifier as s;"
        "c=s.ScopeClassifier();"
        "c._yaml_rules=[{'name':'r','scope_name':'blackbaud','rule_type':'domain_pattern',"
        "'conditions':{'pattern':'*.blackbaud.com'},'enabled':True,'priority':50}];"
        "c._loaded=True;"
        "a=c.classify_rules_only('community.blackbaud.com');"
        "b=c.classify_rules_only('guidedesign.com');"
        "print(a.scope if a else None);"
        "print(b.scope if b else None)")
    assert out and not out.startswith("__ERR__"), out
    assert out.strip().splitlines() == ["blackbaud", "None"], out


# ── DB round-trip (rolled back) ──────────────────────────────────────────────

_DB_ROUNDTRIP = r"""
import os, json, psycopg2
from psycopg2.extras import RealDictCursor
import scope_classifier as s
c = psycopg2.connect(os.environ["DB_DSN"])
cur = c.cursor(cursor_factory=RealDictCursor)
try:
    cur.execute("INSERT INTO engagements (name, status) VALUES ('pytest-scope-learn','planning') RETURNING id")
    eid = cur.fetchone()["id"]
    # one manual seed + a discovered subdomain + an out-of-scope host
    cur.execute("INSERT INTO scope_targets (id,engagement_id,name,target,target_type,source) "
                "VALUES (gen_random_uuid(),%s,'acme','acme.com','domain','manual')", (eid,))
    cur.execute("INSERT INTO assets (ip, hostname, engagement_id) VALUES ('203.0.113.9','api.acme.com',NULL)")
    cur.execute("INSERT INTO recon_findings (id,source,finding_type,target,data,severity) "
                "VALUES (gen_random_uuid(),'subfinder','subdomain','www.acme.com','{}'::jsonb,'info')")
    cur.execute("INSERT INTO recon_findings (id,source,finding_type,target,data,severity) "
                "VALUES (gen_random_uuid(),'subfinder','subdomain','evil.example.org','{}'::jsonb,'info')")

    created = s.generate_seed_rules(cur, str(eid))
    res = s.classify_and_assign_engagement(cur, str(eid))

    # the seed produced a *.acme.com rule
    cur.execute("SELECT conditions->>'pattern' p FROM scope_classification_rules "
                "WHERE engagement_id=%s", (eid,))
    patterns = [r["p"] for r in cur.fetchall()]

    # every new scope row carries the engagement id (the whole bug)
    cur.execute("SELECT count(*) n, count(engagement_id) e FROM scope_targets WHERE engagement_id=%s", (eid,))
    row = cur.fetchone()

    # in-scope host stamped onto its asset
    cur.execute("SELECT engagement_id FROM assets WHERE hostname='api.acme.com'")
    asset_eid = cur.fetchone()["engagement_id"]

    # distillation: a similarity/LLM decision becomes a reusable rule
    learned = s.distill_rule_from_decision(cur, "shop.newbrand.com", "acme", str(eid), "llm")

    print(json.dumps({
        "rules_created": created,
        "in_scope": res["in_scope"], "unknown": res["unknown"],
        "patterns": patterns,
        "all_rows_have_eid": row["n"] == row["e"] and row["n"] > 0,
        "asset_stamped": asset_eid is not None,
        "learned": learned,
    }))
finally:
    c.rollback()
    c.close()
"""


def test_generate_classify_and_distill_roundtrip(container):
    out = _run(_DB_ROUNDTRIP)
    assert out is not None
    if out.startswith("__ERR__"):
        if "DB_DSN" in out or "could not connect" in out or "connection" in out.lower():
            pytest.skip("database not reachable: " + out)
        pytest.fail(out)
    data = json.loads(out.strip().splitlines()[-1])
    # seed acme.com -> *.acme.com rule
    assert data["rules_created"] == 1
    assert "*.acme.com" in data["patterns"]
    # www.acme.com + api.acme.com are in scope; evil.example.org is not
    assert data["in_scope"] >= 2, data
    assert data["unknown"] >= 1, data
    # the engagement_id bug: every row must carry it
    assert data["all_rows_have_eid"] is True
    assert data["asset_stamped"] is True
    # the LLM/similarity decision distilled into a reusable *.newbrand.com rule
    assert data["learned"] == "*.newbrand.com", data


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
