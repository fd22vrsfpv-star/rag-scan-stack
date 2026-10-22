"""2026-10-22: "Hide Blank" hid 88% of the software inventory by default.

Operator, with a screenshot: "under assets for the engagement php doesn't show
anything" — the Software tab, filtered to PHP, read **0 rows, 0 unique
products** directly beneath summary cards saying *13 Assets / 1 Products /
32 Detections* and a Technologies chip reading **PHP 13**. The page
contradicted itself.

The cause was one predicate, on by default:

    hideBlankProductVersion && (!product || !version)   -> hide

In the redteam engagement that hid **9129 of 10360** rows (88%), every one of
them naming a real product, while exactly **1** row genuinely had no product:

    detected_software rows : 10360
      blank VERSION        :  9130   <- hidden
      blank PRODUCT        :     1   <- the only useless row

A product with no version is a real detection — "PHP is running here, version
unknown" is actionable; you go fingerprint it. Only a row with no product name
has nothing to act on.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_software_blank_filter.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
UI = REPO / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx"

pytestmark = pytest.mark.skipif(not UI.exists(), reason="AssetBrowser.tsx not present")


@pytest.fixture(scope="module")
def predicate() -> str:
    src = UI.read_text(encoding="utf-8")
    m = re.search(r"if \(hideBlankProductVersion &&(.{0,200}?)\) return false", src, re.S)
    assert m, "the hide-blank predicate is gone"
    return m.group(1)


def test_a_missing_version_no_longer_hides_the_row(predicate):
    """The whole bug: 9129 rows naming a real product were hidden for lacking
    a version."""
    assert "version" not in predicate, (
        "the filter still drops a row for a missing VERSION: %s" % predicate.strip())


def test_a_missing_product_still_hides_the_row(predicate):
    """It must not swing the other way — a row with no product name has
    nothing to act on and is the one row worth hiding."""
    assert "product" in predicate, (
        "the filter no longer hides rows with no product: %s" % predicate.strip())


def test_the_chip_says_what_it_does():
    """It was labelled "Hide Blank" while hiding named products. A control
    whose label misdescribes it is how this went unnoticed."""
    src = UI.read_text(encoding="utf-8")
    m = re.search(r"setHideBlankProductVersion\(!hideBlankProductVersion\)(.{0,700}?)</button>",
                  src, re.S)
    assert m, "the toggle button was not found"
    block = m.group(1)
    assert "Hide Blank<" not in block, "the chip still claims to hide blanks generally"
    assert "title=" in block, "the chip has no tooltip explaining what it hides"
    assert re.search(r"no version|without a version|no product", block, re.I), \
        "the tooltip does not say which rows are hidden"


def test_the_filter_is_off_by_default():
    """Operator, 2026-10-22: "don't have the hide blank on as the default".

    A row-hiding filter is a poor default on an inventory page — the operator
    cannot miss what they can see, but they can easily miss what a chip
    silently removed. This one was on by default and hid 88% of the rows.
    """
    src = UI.read_text(encoding="utf-8")
    m = re.search(r"hideBlankProductVersion,\s*setHideBlankProductVersion\]\s*=\s*useState\((\w+)\)", src)
    assert m, "the hideBlankProductVersion state declaration was not found"
    assert m.group(1) == "false", \
        "the row-hiding filter is on by default again (useState(%s))" % m.group(1)
