"""Every evidence rule's source table must actually be read.

Run on demand:

    pytest tests/test_wstg_evidence_paths.py -v

WHY THIS EXISTS
---------------
`/coverage/wstg` credits a WSTG test when a finding matches a rule in
knowledge/wstg_coverage_map.yaml. The rules key on a `source` — whatweb, nmap,
katana, gobuster, ffuf, subdomain_takeover — but the query only opened
`web_findings`, `vulns` and `playwright_findings`.

whatweb, httpx, tlsx, subfinder, dnsx and wafw00f write to **recon_findings**, so
those rules could never fire. WSTG-INFO-08/09 (fingerprinting) were reported as
automatable gaps on an engagement that HAD a whatweb finding for the host — work
listed as outstanding that the platform had already done.

This is the third instance of one shape: a rule keyed on a source whose table the
coverage query does not read (playwright_findings filtered on a NULL column;
recon_findings never opened at all). The guard below closes the class: every
`sources:` value in the rule file must map to a table the query reads.

Static — no DB needed, runs in CI.

Sabotage check: drop the recon_findings query from the endpoint -> RED.
"""
import os
import re

import pytest

yaml = pytest.importorskip("yaml")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")
COV_MAP = os.path.join(REPO, "knowledge", "wstg_coverage_map.yaml")

#: Which table each finding source writes to. A source added to the rule file
#: without an entry here fails by name rather than silently never matching.
SOURCE_TABLES = {
    "whatweb": ("recon_findings", "web_findings"),
    "httpx": ("recon_findings", "web_findings"),
    "nmap": ("web_findings", "vulns", "recon_findings"),
    "katana": ("web_findings",),
    "gobuster": ("web_findings",),
    "ffuf": ("web_findings",),
    "subdomain_takeover": ("web_findings", "recon_findings"),
    "playwright": ("playwright_findings",),
    "zap": ("web_findings",),
    "nuclei": ("web_findings",),
    "nikto": ("web_findings",),
    "wafw00f": ("recon_findings", "web_findings"),
}


def _coverage_endpoint_src():
    if not os.path.exists(API):
        pytest.skip("api.py not present")
    src = open(API, encoding="utf-8").read()
    i = src.index("def wstg_coverage")
    j = src.index("wc.compute", i)
    return src[i:j]


def _rules():
    if not os.path.exists(COV_MAP):
        pytest.skip("wstg_coverage_map.yaml not present")
    with open(COV_MAP, encoding="utf-8") as fh:
        rules = (yaml.safe_load(fh) or {}).get("rules") or []
    assert rules, "no rules parsed — this guard would pass vacuously"
    return rules


def _tables_read():
    return set(re.findall(r"FROM public\.(\w+)", _coverage_endpoint_src()))


def test_recon_findings_is_read():
    """The concrete regression: whatweb/httpx land here."""
    assert "recon_findings" in _tables_read(), (
        "the coverage endpoint does not read recon_findings, so every rule keyed "
        "on whatweb/httpx/tlsx/wafw00f can never fire"
    )


def test_every_rule_source_has_a_table_that_is_read():
    read = _tables_read()
    unreachable = {}
    for rule in _rules():
        for src in (rule.get("sources") or []):
            tables = SOURCE_TABLES.get(src)
            assert tables, (
                f"source {src!r} in wstg_coverage_map.yaml has no entry in "
                "SOURCE_TABLES — add the table it writes to, or the rule may "
                "silently never match"
            )
            if not (set(tables) & read):
                unreachable.setdefault(src, rule.get("wstg_id"))
    assert not unreachable, (
        "these rule sources write only to tables the coverage query never reads, "
        f"so the rules can never fire: {unreachable}"
    )


def test_the_query_joins_through_assets_not_a_null_column():
    """playwright_findings.engagement_id is NULL on every row; filtering on it
    silently matched nothing. Every table must be scoped via assets."""
    src = _coverage_endpoint_src()
    for table in ("web_findings", "vulns", "playwright_findings", "recon_findings"):
        if f"FROM public.{table}" not in src:
            continue
        seg = src[src.index(f"FROM public.{table}"):]
        seg = seg[:seg.find('"""')] if '"""' in seg else seg[:400]
        assert "JOIN public.assets" in seg, (
            f"{table} is not scoped through assets — if its own engagement_id "
            "column is unpopulated the filter matches nothing"
        )
