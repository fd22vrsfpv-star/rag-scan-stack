"""nuclei must not be deduplicated away, and local template fixes must load.

Two defects this pins, both of which present as "the target is not vulnerable":

1. `web_vuln_scan: [nikto, nuclei]` in knowledge/service_tools.yaml. An overlap
   group is an OR — recommend one, not all — so nikto won every time and nuclei
   was dropped from every web recommendation. They are not interchangeable:
   nikto checks misconfigurations and known paths, nuclei runs ~14k templates
   including CVE-specific exploit checks. A WordPress host with a verified
   nuclei template for CVE-2024-5084 (CVSS 9.8) produced eight web
   recommendations, none of which could have found it.

2. `_get_detected_tech` read only `data.tech[]`/`data.webserver` from
   recon_findings, and filtered on `data->>'port'`. whatweb's NATIVE rows carry
   neither: tech lives in `plugins` and the port only inside the `target` URL.
   So a row that plainly said `WordPress: 6.8.3` produced no tokens, no
   tech_signature match, and no CMS-targeted nuclei tags — the detection sat in
   the database and nothing could see it.

*Enforced by:* this file.
"""
import os

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml not installed here")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
KB = os.path.join(REPO, "knowledge", "service_tools.yaml")
RUNNER = os.path.join(REPO, "nuclei", "nuclei_runner.py")


def _kb():
    if not os.path.exists(KB):
        pytest.skip("service_tools.yaml not present")
    with open(KB, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _groups():
    return ((_kb().get("tool_metadata") or {}).get("overlap_groups") or {})


def test_nuclei_is_not_in_any_overlap_group():
    """An overlap group drops all but one member — nuclei must never be the
    one dropped, because nothing else carries CVE templates."""
    offenders = [name for name, g in _groups().items()
                 if "nuclei" in (g.get("members") or [])]
    assert not offenders, (
        "nuclei is a member of overlap group(s) "
        f"{offenders}; an overlap group recommends ONE member, so nuclei gets "
        "dropped and CVE-specific detection silently stops running. nikto is "
        "not a substitute: it checks misconfigurations, not CVEs.")


def test_nikto_group_survives():
    """The guard must not pass by deleting the group wholesale."""
    g = _groups().get("web_vuln_scan")
    assert g, "web_vuln_scan group removed entirely; nikto's dedup is still wanted"
    assert "nikto" in (g.get("members") or []), "nikto dropped from web_vuln_scan"


def test_http_service_still_offers_nuclei():
    """The http service entry must actually list nuclei for any of this to matter."""
    svc = (_kb().get("services") or {}).get("http") or {}
    names = {t.get("name") for t in (svc.get("tools") or [])}
    assert "nuclei" in names, (
        f"the http service no longer lists nuclei as a tool (has: {sorted(names)})")


# ── Enriched service: the recon_findings shape contract ─────────────────────
# `_get_detected_tech` turns persisted httpx/whatweb output into tech tokens
# that `tech_signatures` matches, which is what produces CMS-targeted nuclei
# tags (wordpress -> wordpress,wp-plugin,wp-theme). It read ONLY `data.tech[]`
# and `data.webserver`, and filtered on `data->>'port'` — none of which exist
# on whatweb's native rows. Verified on a live target: whatweb had recorded
# `WordPress: {version: [6.8.3]}` on port 9090 and the recommender saw nothing.

RECOMMENDER = os.path.join(REPO, "scan_recommender", "scan_recommender.py")


def _load_tech_helpers():
    if not os.path.exists(RECOMMENDER):
        pytest.skip("scan_recommender.py not present")
    src = open(RECOMMENDER, encoding="utf-8").read()
    try:
        start = src.index("def _row_port")
        end = src.index("def _get_detected_tech")
    except ValueError:
        pytest.skip("tech helpers not found")
    from typing import List, Optional
    ns = {"Optional": Optional, "List": List}
    exec(compile(src[start:end], RECOMMENDER, "exec"), ns)  # noqa: S102
    return ns["_row_port"], ns["_tech_tokens_from_row"]


#: The exact shape whatweb persists — no `port` key, tech under `plugins`.
WHATWEB_ROW = {
    "target": "http://172.19.21.5:9090", "http_status": 200,
    "plugins": {"WordPress": {"version": ["6.8.3"]},
                "Apache": {"version": ["2.4.65"]},
                "Title": {"string": ["My WordPress Site"]}},
}


def test_port_resolves_from_target_when_there_is_no_port_key():
    row_port, _ = _load_tech_helpers()
    assert row_port(WHATWEB_ROW) == 9090, (
        "whatweb rows carry the port only inside `target`; losing it filters "
        "out exactly the rows holding the CMS detection")
    assert row_port({"port": 8080}) == 8080
    assert row_port({"target": "https://h/"}) == 443
    assert row_port({"target": "http://h/"}) == 80
    assert row_port({}) is None


def test_wordpress_is_extracted_from_the_plugins_shape():
    _, toks = _load_tech_helpers()
    t = toks(WHATWEB_ROW)
    assert "WordPress" in t, (
        f"WordPress not extracted from whatweb's plugins shape; got {t}")
    assert "WordPress 6.8.3" in t, (
        "the version token is missing — a CVE lookup needs product+version")


def test_the_httpx_shape_still_works():
    """The original shape must not regress while adding the others."""
    _, toks = _load_tech_helpers()
    t = toks({"port": 9090, "tech": ["WordPress", "PHP"],
              "webserver": "Apache/2.4.65"})
    assert "WordPress" in t and "Apache/2.4.65" in t


def test_wordpress_tokens_match_a_tech_signature_with_wp_plugin_tag():
    """End of the chain: the token must reach the tag that selects the CVE
    template. CVE-2024-5084 is tagged wp-plugin."""
    sigs = _kb().get("tech_signatures") or {}
    wp = sigs.get("wordpress")
    assert wp, "no wordpress tech_signature"
    assert any("wordpress" in m.lower() for m in (wp.get("match") or [])), (
        "the wordpress signature cannot match a 'WordPress' token")
    assert "wp-plugin" in (wp.get("nuclei_tags") or []), (
        "wordpress no longer yields the wp-plugin tag; CVE-2024-5084 and every "
        "other plugin CVE template becomes unreachable")


# ── Recommendation coverage is per (ip, service, PORT) ─────────────────────
# scan_recommendations had no `port` column, so the "which ports still need a
# recommendation" query joined on (ip, service). A host with several ports
# running the same service — an app on 9090 plus harness ports on 8000/9091,
# all 'http' — counted as covered the moment ANY one of them was recommended.
# Observed on a live target: 1 of 5 ports considered; after the fix, 4.

API = os.path.join(REPO, "app", "rag-api", "api.py")
RECO = os.path.join(REPO, "scan_recommender", "scan_recommender.py")
DDL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")


def _read(p):
    if not os.path.exists(p):
        pytest.skip(f"{os.path.basename(p)} not present")
    return open(p, encoding="utf-8").read()


def test_coverage_query_keys_on_port():
    src = _read(API)
    i = src.find("LEFT JOIN public.scan_recommendations sr")
    assert i != -1, "the coverage LEFT JOIN is gone"
    join = src[i:i + 400]
    assert "sr.port" in join, (
        "the coverage query no longer keys on port; ports sharing a service "
        "will be treated as covered by one another and never scanned")
    assert "sr.port IS NULL" in join, (
        "rows written before the port column must still suppress, or the fix "
        "re-queues work that was already done")


def test_writer_persists_the_port_column():
    src = _read(RECO)
    i = src.find("INSERT INTO public.scan_recommendations")
    assert i != -1, "the recommendation INSERT is gone"
    stmt = src[i:i + 500]
    assert "port" in stmt.split("VALUES")[0], (
        "port is not in the INSERT column list; the coverage query would see "
        "NULL for every new row and the dedup silently reverts")
    assert "rec_port" in src, "rec_port is never computed"


def test_schema_declares_port_and_backfills_it():
    ddl = _read(DDL)
    i = ddl.find("CREATE TABLE IF NOT EXISTS public.scan_recommendations")
    assert i != -1
    block = ddl[i:i + 4000]
    assert "port        integer" in block or "port integer" in block, (
        "scan_recommendations.port missing from the table definition")
    assert "ADD COLUMN IF NOT EXISTS port integer" in ddl, (
        "existing installs get no port column; the dedup fix is a no-op there")
    assert "extra->>'port'" in ddl, (
        "no backfill from where the port was already being written, so rows "
        "created before the column keep suppressing every port on their service")
