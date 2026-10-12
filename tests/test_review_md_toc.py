"""The review.md export carries a linked index of its sections.

`_md_toc` derives the index from the headings actually emitted, not from a fixed
list, because nearly every section in a review is conditional — a hardcoded
index would advertise sections a given report does not contain and silently omit
new ones.

Two things it must get right or the links are dead:
  * anchors must match GitHub's slug rules, including the -1/-2 suffixing that
    disambiguates repeated headings;
  * a "## ..." line inside a fenced code block is NOT a heading. Command output
    and captured HTTP bodies routinely contain lines starting with #.

Guards `_md_github_slug` + `_md_toc` in `app/rag-api/api.py`. Loaded by source
extraction rather than import: api.py pulls in the whole service on import.
"""
import os
import re as _re_module

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _load():
    """Exec just the two helpers out of api.py, with `re` available as the
    alias api.py uses (`_re_module`) so this matches the real runtime names."""
    if not os.path.exists(API):
        pytest.skip("api.py not present")
    src = open(API, encoding="utf-8").read()
    try:
        start = src.index("def _md_github_slug")
        end = src.index("def _render_review_md")
    except ValueError:
        pytest.skip("review-md helpers not found in api.py")
    ns = {"_re_module": _re_module}
    exec(compile(src[start:end], API, "exec"), ns)  # noqa: S102
    return ns["_md_toc"], ns["_md_github_slug"]


def test_indexes_the_headings_present():
    toc, _ = _load()
    body = ["# Title", "", "## Failure analysis", "", "## sqlmap hand-off", ""]
    out = "\n".join(toc(body))
    assert "## Contents" in out
    assert "- [Failure analysis](#failure-analysis)" in out
    assert "- [sqlmap hand-off](#sqlmap-hand-off)" in out


def test_slug_matches_github_rules():
    _, slug = _load()
    seen = {}
    assert slug("Confirmed facts (12)", seen) == "confirmed-facts-12"
    assert slug("Ranked next steps (manual continuation)", {}) == \
        "ranked-next-steps-manual-continuation"
    assert slug("sqlmap hand-off", {}) == "sqlmap-hand-off"


def test_duplicate_headings_get_github_suffixes():
    """Two identical headings must not both link to the same anchor."""
    _, slug = _load()
    seen = {}
    assert slug("Confirmed facts (12)", seen) == "confirmed-facts-12"
    assert slug("Confirmed facts (12)", seen) == "confirmed-facts-12-1"
    assert slug("Confirmed facts (12)", seen) == "confirmed-facts-12-2"


def test_headings_inside_code_fences_are_not_indexed():
    """A '## ...' line in captured output is content, not a section."""
    toc, _ = _load()
    body = [
        "## Real section", "",
        "```", "## not a heading", "# also not", "```", "",
        "## Another real section", "",
    ]
    out = "\n".join(toc(body))
    assert "not a heading" not in out, "indexed a heading inside a code fence"
    assert "- [Real section](#real-section)" in out
    assert "- [Another real section](#another-real-section)" in out


def test_nesting_is_indented():
    toc, _ = _load()
    body = ["## Top", "", "### Child", "", "## Second", ""]
    lines = toc(body)
    child = [ln for ln in lines if "Child" in ln][0]
    top = [ln for ln in lines if "[Top]" in ln][0]
    assert child.startswith("  "), "### should be indented under ##"
    assert not top.startswith(" "), "## should not be indented"


def test_no_index_when_there_is_nothing_to_index():
    """A one-section report does not need a table of contents."""
    toc, _ = _load()
    assert toc(["# Title", "", "## Only section", ""]) == []
    assert toc(["# Title", "", "no headings at all"]) == []


def test_every_toc_anchor_resolves_to_a_heading():
    """End-to-end: each generated link must point at a heading in the body."""
    toc, slug = _load()
    body = [
        "## Failure analysis", "", "### Blockers (3)", "",
        "## Confirmed facts (12)", "", "## Confirmed facts (12)", "",
        "## sqlmap hand-off", "",
    ]
    lines = toc(body)
    anchors = [m.group(1) for ln in lines
               if (m := _re_module.search(r"\]\(#([^)]+)\)", ln))]
    seen = {}
    expected = [slug(_re_module.match(r"^#{2,3}\s+(.*\S)\s*$", b).group(1), seen)
                for b in body if _re_module.match(r"^#{2,3}\s+\S", b)]
    assert anchors == expected, (
        f"TOC anchors do not match the headings they should point at:\n"
        f"  toc:      {anchors}\n  headings: {expected}")
