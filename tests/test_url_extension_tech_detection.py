"""2026-10-22: a crawled URL's extension is evidence of the server-side runtime.

Operator: "I would expect that php would have shown up on more assets", then
"there should be other indicators outside of wordpress, does katana, httpx or
playwright".

Every PHP detection came from httpx or gowitness TECH fingerprints, which read
`X-Powered-By` — so PHP was found only where the server still advertises it.
Katana alone had 6705 crawled URLs including 498 distinct `.php` and 255 `.jsp`,
and nothing mined them: the existing katana branches (Sources 9/10) read URLs
for versioned JS/CSS libraries only.

Adding the branch took PHP from **31 to 40** hosts with no new scanning — the
inventory is a VIEW, so the backport is automatic over data already collected.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_url_extension_tech_detection.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DDL = REPO / "db_init" / "ensure_all_tables.sql"


@pytest.fixture(scope="module")
def branch() -> str:
    sql = DDL.read_text()
    i = sql.find("-- Source 16: SERVER-SIDE RUNTIME")
    assert i > 0, "the url_extension branch is gone from the view"
    j = sql.index(") _software", i)
    return sql[i:j]


def test_the_branch_is_inside_the_detected_software_view():
    sql = DDL.read_text()
    v = sql.index("CREATE OR REPLACE VIEW public.detected_software AS")
    end = sql.index("detection_type;", v)
    assert v < sql.find("-- Source 16: SERVER-SIDE RUNTIME") < end, \
        "the branch is not inside the view definition"


@pytest.mark.parametrize("ext,product", [
    ("php", "PHP"), ("phtml", "PHP"), ("php5", "PHP"),
    ("jsp", "JSP"), ("jspx", "JSP"), ("aspx", "ASP.NET"),
    ("asp", "Classic ASP"), ("cfm", "ColdFusion"), ("cgi", "CGI"),
    ("pl", "Perl"), ("py", "Python"), ("rb", "Ruby"),
])
def test_each_runtime_is_mapped(branch, ext, product):
    assert re.search(rf"WHEN\s+'{ext}'\s+THEN\s+'{re.escape(product)}'", branch), \
        f".{ext} does not map to {product}"
    # and the WHERE clause must actually admit it
    m = re.search(r"~\*\s*'\\\.\(([^)]+)\)\$'", branch)
    assert m, "no extension filter found"
    alts = m.group(1)
    assert ext in alts or re.search(rf"{ext[:3]}\w*\??", alts), \
        f".{ext} is mapped but never matched: {alts}"


def test_the_extension_is_read_from_the_path_only(branch):
    """`?file=x.php` is a PARAMETER, not a handler, and `.do`/`.pl` are also
    ccTLDs — matching the whole URL would call `https://example.do/` a Struts
    app."""
    assert "://[^/]+(/[^?#]*)" in branch, \
        "the extension is not extracted from the path portion"
    assert branch.count("://[^/]+(/[^?#]*)") >= 2, \
        "the CASE and the WHERE must both read the path, or they disagree"


def test_the_match_is_anchored_to_end_of_path(branch):
    """`.php.bak` and `.jsp.old` are backups, not live handlers."""
    m = re.search(r"~\*\s*'\\\.\([^)]+\)\$'", branch)
    assert m, "the extension filter is not anchored with $"


def test_no_version_is_invented(branch):
    """An extension names the runtime, never its version — a guess here would
    feed the CVE lookup a version nobody observed."""
    assert re.search(r"NULL::text\s+AS\s+version", branch), \
        "the branch emits a version it cannot know"


def test_it_is_not_limited_to_katana(branch):
    """The extension is evidence whoever crawled it. Hard-coding 'katana' would
    discard the same signal from zap / gobuster / feroxbuster / playwright."""
    assert re.search(r"wf\.source\b", branch), "the source is not carried through"
    assert not re.search(r"wf\.source\s*=\s*'katana'", branch), \
        "the branch is restricted to katana"


def test_it_is_labelled_as_its_own_detection_type(branch):
    """So an operator can tell a crawled-path inference from a header claim."""
    assert "'url_extension' AS detection_type" in branch


def test_the_existing_katana_js_branches_survive():
    """Sources 9 and 10 mine versioned JS/CSS from the same table; this must be
    an addition, not a replacement."""
    sql = DDL.read_text()
    assert "-- Source 9: Katana JS/CSS versioned libraries" in sql
    assert "-- Source 10: Katana JS/CSS versioned filenames" in sql
    assert sql.count("'js_library' AS detection_type") >= 1
