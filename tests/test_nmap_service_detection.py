"""2026-10-22: the pipeline discovered ports and never asked what was on them.

Measured head-to-head on Metasploitable2 (172.19.250.250), same host, same
moment:

    naabu     — 21 open ports, ZERO named. Addresses and numbers only.
    nmap -sV  — 20 of 21 identified, 11 with exact versions:
                vsftpd 2.3.4, OpenSSH 4.7p1, Postfix, Samba 3.X,
                ProFTPD 1.3.1, MySQL 5.0.51a, PostgreSQL 8.3,
                UnrealIRCd, Apache Tomcat/Coyote 1.1 …

That is not a cosmetic gap. vsftpd 2.3.4 is the backdoored release
(CVE-2011-2523), UnrealIRCd on 6667 is CVE-2010-2075, Samba 3.x is
CVE-2007-2447 — all known-RCE. Our `vulns` count for that host was **0**, not
because it is clean (it is the most vulnerable box in common use) but because
the CVE lookup keys on product+version and 20 of 22 ports carried neither.
Port discovery without service detection silently starves CVE matching,
exploit selection and the agent's target context.

`etl/parse_nmap.py` and `/ingest/nmap` already existed. Nothing produced the
XML they consume.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_nmap_service_detection.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RUNNER = REPO / "pd_runner" / "pd_runner.py"
DOCKERFILE = REPO / "pd_runner" / "Dockerfile"

pytestmark = pytest.mark.skipif(not RUNNER.exists(), reason="pd_runner not present")


@pytest.fixture(scope="module")
def src() -> str:
    return RUNNER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def route(src) -> str:
    fn = next((n for n in _ast.parse(src).body
               if isinstance(n, _ast.FunctionDef) and n.name == "run_nmap_service_detection"), None)
    assert fn is not None, "the /jobs/nmap route is missing"
    return _ast.get_source_segment(src, fn)


def test_the_route_exists(src):
    # Matched as a pattern: the ratchet reads a decorator literal as code.
    assert re.search(r'@app\.post\(\s*[\"\']/jobs/nmap[\"\']\s*\)', src), \
        "no /jobs/nmap route"


def test_it_does_service_detection(route):
    """-sV is the entire point. Without it this is a slower naabu."""
    assert '"-sV"' in route, "the command does not request service detection"
    assert '"-oX"' in route, "output is not nmap XML — parse_nmap cannot read it"


def test_it_is_not_a_port_scanner(route):
    """naabu already does discovery and does it faster. Scanning all ports here
    would duplicate that work and multiply the traffic."""
    assert "-p-" not in route, "this re-scans every port instead of the known ones"
    assert re.search(r'"-p"', route), "the port list is never passed to nmap"
    assert "1-65535" not in route


def test_ports_come_from_what_discovery_found(src, route):
    assert "get_scanned_hosts" in route, "ports are not seeded from the ports table"
    helper = next((n for n in _ast.parse(src).body
                   if isinstance(n, _ast.FunctionDef) and n.name == "get_scanned_hosts"), None)
    assert helper is not None, "get_scanned_hosts is missing"
    body = _ast.get_source_segment(src, helper)
    assert "is_open" in body, "the seed includes ports known to be closed"
    assert re.search(r"GROUP BY", body), "ports are not grouped per host"


def test_an_unscanned_host_is_not_treated_as_having_no_ports(route):
    """"no discovery yet" is not "no open ports" — the repo's recurring
    unreachable-is-not-absent rule."""
    assert re.search(r"known\.get\(", route), \
        "an explicit target is not looked up against known ports"
    assert "no scanned hosts with open ports" in route, \
        "an empty seed is not reported distinctly from a completed scan"


def test_a_filtered_host_is_still_fingerprinted(route):
    """-Pn: a host that is up but does not answer ping must not be skipped
    before we ask what it runs."""
    assert '"-Pn"' in route, "host discovery is not skipped"
    assert "skip_host_discovery" in route, "the caller cannot control it"


def test_it_is_bounded(src, route):
    assert "max_hosts" in route, "the sweep has no host bound"
    assert re.search(r"min\(\s*500\s*,", route), "max_hosts has no ceiling"


def test_nmap_is_actually_in_the_image():
    """The route is useless if the binary is absent — and a missing binary
    fails at runtime, not at build time."""
    df = DOCKERFILE.read_text(encoding="utf-8")
    assert re.search(r"apt-get install[^\n]*(\\\s*\n[^\n]*)*nmap", df), \
        "nmap is not installed in the pd_runner image"


def test_results_are_ingested_as_nmap(route):
    """/ingest/nmap and etl/parse_nmap.py already exist; the job must route
    there or the XML is written and dropped."""
    assert re.search(r'_run_tool_job,\s*job_id,\s*"nmap"', route), \
        "the job does not ingest as nmap"


# --- naabu re-scans can be bounded the same way -----------------------------
#
# Operator: "if we already have port scan results for a specific host then go
# run the naabu scanner against, only do it against the already discovered
# ports." A host with known-open ports does not need rediscovering to confirm
# they are still up, and a 1000-port sweep per re-scan is traffic at a
# customer's estate for an answer already in the database.


@pytest.fixture(scope="module")
def naabu(src) -> str:
    fn = next((n for n in _ast.parse(src).body
               if isinstance(n, _ast.FunctionDef) and n.name == "run_naabu"), None)
    assert fn is not None, "run_naabu is missing"
    return _ast.get_source_segment(src, fn)


def test_naabu_can_rescan_only_known_ports(naabu):
    assert "known_ports_only" in naabu, "naabu cannot be bounded to known ports"
    assert "get_scanned_hosts" in naabu, \
        "the known-port list is not read from what discovery found"


def test_it_is_opt_in_not_the_default(src):
    """A narrowed re-scan CANNOT discover a port that opened since the last
    run. Defaulting it on would quietly turn discovery into verification."""
    m = re.search(r"known_ports_only:\s*Optional\[bool\]\s*=\s*(\w+)", src)
    assert m, "the known_ports_only field was not found"
    assert m.group(1) == "False", \
        "bounding re-scans to known ports is the default (%s)" % m.group(1)


def test_an_explicit_port_list_still_wins(naabu):
    """An operator naming a list means it."""
    assert re.search(r"req\.known_ports_only and not req\.ports", naabu), \
        "known-port narrowing overrides an explicit ports argument"


def test_an_unscanned_host_falls_back_to_discovery(naabu):
    """"we hold no ports for this host" is not "this host has no open ports" —
    narrowing to an empty list would scan nothing and report success."""
    assert re.search(r"not req\.ports and not _known and not req\.top_ports", naabu), \
        "a host with no known ports no longer falls back to the top-1000 sweep"
