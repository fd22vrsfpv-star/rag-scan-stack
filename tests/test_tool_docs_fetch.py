"""Web docs for tool invocations: fetched, flagged, and RAG-ingested.

Run on demand:

    pytest tests/test_tool_docs_fetch.py -v

WHY THIS EXISTS
---------------
The runtime command check found 52 catalogue tools absent from the image it
probed and 10 httpx commands carrying another program's flags. Deciding what to
do about each needs to know what the tool IS, so `scripts/fetch_tool_docs.py`
pulls kali.org's page per tool through the EXISTING fetcher
(`scan_recommender/url_fetch`), which already has the scheme allowlist, SSRF
guard, size/redirect caps and HTML→markdown extraction.

Three things here were learned the hard way and are worth keeping:

  * **The index needs RAW HTML.** `extract_markdown()` turns links into text, so
    fetching https://www.kali.org/tools/ as markdown yields 12,577 characters of
    prose and ZERO tool slugs. Fetched as HTML it yields 421.
  * **The index is INCOMPLETE.** `whois` has a page that is not listed in it. An
    index miss is therefore not proof of absence, so a direct-URL attempt has to
    follow — resolving by index alone lost two tools the naive guess had found.
  * **Some tools are subcommand-first.** gobuster's `-w` is not in
    `gobuster --help`; it is in `gobuster dir --help`. That single fact is why
    help-text flag validation was abandoned, and it is now detected from the
    doc's own COMMANDS: block and flagged so a caller — or a model drafting one —
    puts the subcommand before the flags.
"""
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(REPO, "scripts", "fetch_tool_docs.py")
DOCS = os.path.join(REPO, "knowledge", "commands", "kali_tool_docs.md")
sys.path.insert(0, os.path.join(REPO, "scripts"))


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


# ── the fetcher reuses, and stays safe ──────────────────────────────────────

@pytest.mark.unit
def test_it_reuses_the_existing_fetcher():
    """url_fetch already has the SSRF guard, caps and markdown extraction.

    A second fetcher would have to re-earn all of that.
    """
    src = open(SCRIPT, encoding="utf-8").read()
    assert "from url_fetch import fetch_guide" in src
    assert "from url_fetch import fetch_url" in src
    assert "requests.get" not in src and "urllib.request" not in src, \
        "a hand-rolled fetch appeared; use url_fetch so the guards apply"


@pytest.mark.unit
def test_the_index_is_read_as_raw_html():
    """Markdown extraction destroys links, and an index page IS links."""
    src = open(SCRIPT, encoding="utf-8").read()
    idx = src.split("_INDEX_SNIPPET", 1)[1][:600]
    assert "fetch_url" in idx and '["html"]' in idx, \
        "the index is no longer read as HTML; slug extraction will find nothing"


@pytest.mark.unit
def test_an_index_miss_still_tries_the_direct_url():
    """The index omits `whois`, so a miss is not proof of absence."""
    src = open(SCRIPT, encoding="utf-8").read()
    assert "index miss, tried direct" in src, \
        "an index miss now ends the attempt; tools with unlisted pages are lost"


@pytest.mark.unit
def test_an_ambiguous_slug_is_reported_not_guessed():
    """A wrong page reads as authoritative documentation for the wrong tool."""
    from fetch_tool_docs import resolve_slug
    slug, how = resolve_slug("nmap", ["nmap", "nmap-common", "ndiff"])
    assert (slug, how) == ("nmap", "exact")
    slug, how = resolve_slug("zzz", ["zzz-a", "zzz-b"])
    assert slug is None and "ambiguous" in how, \
        f"an ambiguous name was resolved to {slug!r} instead of reported"
    slug, how = resolve_slug("nothinglikethis", ["nmap", "hydra"])
    assert slug is None


# ── subcommand-first detection ──────────────────────────────────────────────

@pytest.mark.unit
def test_subcommands_are_detected_from_the_doc():
    from fetch_tool_docs import detect_subcommands
    body = (
        "COMMANDS:\n"
        "   dir      Uses directory/file enumeration mode\n"
        "   vhost    Uses VHOST enumeration mode\n"
        "   dns      Uses DNS subdomain enumeration mode\n"
        "   help, h  Shows a list of commands\n"
        "\nGLOBAL OPTIONS:\n   --help, -h   show help\n")
    subs = detect_subcommands(body)
    assert subs == ["dir", "dns", "vhost"], subs
    assert "help" not in subs, "`help` is not a scanning subcommand"
    assert detect_subcommands("no commands block here") == []


@pytest.mark.unit
def test_a_command_missing_its_subcommand_is_flagged():
    """`gobuster -u ... -w ...` cannot work, and a yaml diff will not show it."""
    from fetch_tool_docs import check_subcommand_use
    subs = ["dir", "dns", "fuzz", "vhost"]
    assert check_subcommand_use("gobuster", subs,
                                ["gobuster dir -u http://x -w /l"]) == []
    bad = check_subcommand_use("gobuster", subs, [
        "gobuster -u http://x -w /l", "gobuster --wordlist /l", "gobuster"])
    assert len(bad) == 3, f"a subcommand-less invocation slipped through: {bad}"


# ── the record, and its ingestion ───────────────────────────────────────────

def test_the_record_flags_gobuster_and_names_its_subcommands():
    if not os.path.exists(DOCS):
        pytest.skip("kali_tool_docs.md not generated in this checkout")
    body = open(DOCS, encoding="utf-8").read()
    assert "### gobuster" in body
    assert "subcommand-first" in body, \
        "gobuster is documented but not flagged as needing a subcommand"
    for sub in ("dir", "vhost", "dns"):
        assert sub in body
    assert "tools that require a subcommand" in body, \
        "the summary a caller would actually read is gone"


def test_each_tool_appears_as_exactly_one_section():
    """The fetched markdown carries its own `### <tool>` heading.

    Left in place, every tool got two sections and two Source lines, which
    defeats one-section-per-tool chunking — an answer about gobuster could then
    be assembled from half of it.
    """
    if not os.path.exists(DOCS):
        pytest.skip("kali_tool_docs.md not generated in this checkout")
    heads = re.findall(r"^### (\S+)", open(DOCS, encoding="utf-8").read(),
                       flags=re.M)
    tools = [h for h in heads if h not in ("tools",)]
    dupes = {t for t in tools if tools.count(t) > 1}
    assert not dupes, f"duplicated sections for {sorted(dupes)}"


def test_the_record_was_ingested():
    """'For RAG' is a claim; this is the evidence."""
    n = _psql("SELECT count(*) FROM exploit_chunks "
              "WHERE chunk ILIKE '%subcommand-first%'")
    if n is None:
        pytest.skip("no reachable rag-postgres")
    assert int(n) > 0, (
        "no chunk carries the subcommand flag — run POST /rag/playbooks/ingest "
        "with {\"playbook_dir\": \"/knowledge/commands\"}")
