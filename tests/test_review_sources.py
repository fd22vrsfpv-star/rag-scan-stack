"""2026-10-09: the review.md research section links to the pages things were
found on.

`_review_source_links(md, intel, target_host)` collects every URL the research
touched — NVD references, Exploit-DB / Metasploit ids, the derived spec, manual
research hits, and every trace phase — tagged with where it was found,
deduplicated, with target / private / local addresses dropped. Pure
(AST-loaded) on the real shape `exploit_store.metadata.research_sources` has
(CVE-2024-4443: duplicated NVD refs to Wordfence + plugin trac).

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_review_sources.py -v'
"""
from __future__ import annotations

import ast as _ast
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


def _load(names):
    src = API.read_text()
    tree = _ast.parse(src)
    ns: dict = {"json": json, "_REVIEW_URL_RE": None}
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


@pytest.fixture(scope="module")
def links():
    return _load(["_review_source_links"])["_review_source_links"]


# Real research_sources shape from exploit_store (CVE-2024-4443), refs duplicated as stored.
MD = {
    "research_sources": {
        "msf": [], "exploitdb": ["51234"],
        "nvd_refs": [
            "https://plugins.trac.wordpress.org/browser/business-directory-plugin/trunk/includes/fields/class-fieldtypes-select.php#L110",
            "https://plugins.trac.wordpress.org/changeset/3089626/",
            "https://www.wordfence.com/threat-intel/vulnerabilities/id/982fb304-08d6-4195-97a3-f18e94295492?source=cve",
            "https://plugins.trac.wordpress.org/changeset/3089626/",
        ],
        "has_advisory_text": True, "has_public_module": False,
    },
    "research": {"summary": "SQLi in class-fieldtypes-select.php", "seed_command": "curl http://172.18.0.11:9090/business-directory/"},
    "manual_research_queries": [
        {"query": "business directory sqli poc", "results": [
            {"title": "GHSA advisory", "url": "https://github.com/advisories/GHSA-xxxx", "text": "see https://patchstack.com/database/vulnerability/business-directory-plugin/x"},
        ]},
    ],
}
INTEL = {
    "derived_spec": {"spec": {"advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-4443", "transport": "http"}},
    "full_trace": [
        {"phase": "research", "response": "References: https://www.wordfence.com/threat-intel/vulnerabilities/id/982fb304-08d6-4195-97a3-f18e94295492?source=cve, https://example.org/writeup"},
        {"phase": "run", "response": "curl http://172.18.0.11:9090/x?id=1 ; see https://should-not-appear.example/run"},
        {"phase": "recon:port_sweep", "response": "Open ports on 172.18.0.11 … check success with curl -s http://172.18.0.11:9091/done"},
        {"phase": "gather_check", "response": "x", "extra": {"gather_manifest": {"facts": {"poc_hints": "sink at http://target:9091/upload; see https://cve-bench.example/docs"}}}},
    ],
}


def test_collects_tagged_deduplicated_links(links):
    rows = links(MD, INTEL, target_host="172.18.0.11")
    urls = [u for _, u in rows]
    # deduplicated, first occurrence wins, NVD refs first
    assert urls[:3] == [
        "https://plugins.trac.wordpress.org/browser/business-directory-plugin/trunk/includes/fields/class-fieldtypes-select.php#L110",
        "https://plugins.trac.wordpress.org/changeset/3089626/",
        "https://www.wordfence.com/threat-intel/vulnerabilities/id/982fb304-08d6-4195-97a3-f18e94295492?source=cve",
    ]
    assert len(urls) == len(set(urls))
    via = dict((u, v) for v, u in rows)
    assert via[urls[0]] == "NVD reference"
    assert via["https://www.exploit-db.com/exploits/51234"] == "Exploit-DB"
    assert via["https://nvd.nist.gov/vuln/detail/CVE-2024-4443"] == "derived CVE spec"
    assert via["https://github.com/advisories/GHSA-xxxx"].startswith("manual research:")
    assert via["https://patchstack.com/database/vulnerability/business-directory-plugin/x"].startswith("manual research:")
    assert via["https://example.org/writeup"] == "trace: research"
    assert via["https://cve-bench.example/docs"] == "trace: gather_check"


def test_target_private_and_run_phase_urls_are_excluded(links):
    rows = links(MD, INTEL, target_host="172.18.0.11")
    urls = [u for _, u in rows]
    assert not any("172.18." in u or "target:" in u or "localhost" in u for u in urls)
    assert not any("should-not-appear" in u for u in urls)      # run/refine/synth phases are commands, not sources


def test_total_on_empty_and_garbage(links):
    assert links({}, {}, None) == []
    assert links({"research_sources": "nope"}, {"full_trace": [{"phase": "research", "response": None}]}, None) == []


def test_renderer_emits_the_sources_section():
    src = API.read_text()
    assert '### Sources (' in src and "_review_source_links(md, intel, target_host=" in src
