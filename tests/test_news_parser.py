"""
News intelligence — pure-function tests (no DB).

Covers:
  * CVE regex extraction from titles + body
  * fingerprint stability + collision (same CVE + similar title → one row)
  * RSS parsing via feedparser fixture round-trip
  * LLM JSON tolerant extraction
  * boolean coercion
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "news_sample")


def _import_agent():
    """Lazy import — news_runner module isn't on sys.path by default."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "news_runner"))
    import news_agent  # type: ignore
    return news_agent


# ----------------------------------------------------------------------------
# CVE extraction
# ----------------------------------------------------------------------------

def test_extract_cves_basic():
    na = _import_agent()
    out = na._extract_cves("Critical RCE in WidgetCorp Acme Server CVE-2099-12345", "")
    assert "CVE-2099-12345" in out


def test_extract_cves_case_insensitive():
    na = _import_agent()
    out = na._extract_cves("low-case cve-2099-12345 in body", "another body")
    # Output is normalized to upper case
    assert "CVE-2099-12345" in out


def test_extract_cves_dedup_across_texts():
    na = _import_agent()
    out = na._extract_cves(
        "title CVE-2099-12345",
        "body mentions CVE-2099-12345 again and CVE-2099-99999",
    )
    assert sorted(out) == ["CVE-2099-12345", "CVE-2099-99999"]


def test_extract_cves_none():
    na = _import_agent()
    assert _import_agent()._extract_cves("just a generic story about ransomware", "") == []


# ----------------------------------------------------------------------------
# Fingerprinting / dedup
# ----------------------------------------------------------------------------

def test_fingerprint_stable_for_same_inputs():
    na = _import_agent()
    fp1 = na._fingerprint("CVE-2099-12345", na._normalize_title("Critical RCE in WidgetCorp Acme Server"))
    fp2 = na._fingerprint("CVE-2099-12345", na._normalize_title("Critical RCE in WidgetCorp Acme Server"))
    assert fp1 == fp2


def test_fingerprint_collapses_punctuation():
    na = _import_agent()
    fp1 = na._fingerprint("CVE-2099-12345", na._normalize_title("Critical RCE in WidgetCorp Acme Server!"))
    fp2 = na._fingerprint("CVE-2099-12345", na._normalize_title("Critical: RCE in WidgetCorp Acme Server"))
    assert fp1 == fp2


def test_fingerprint_differs_when_cve_changes():
    na = _import_agent()
    title = na._normalize_title("Same title here")
    assert na._fingerprint("CVE-2099-12345", title) != na._fingerprint("CVE-2099-99999", title)


def test_fingerprint_no_cve_uses_title_only():
    na = _import_agent()
    fp_a = na._fingerprint(None, na._normalize_title("Generic ransomware update"))
    fp_b = na._fingerprint(None, na._normalize_title("Generic ransomware update"))
    fp_c = na._fingerprint(None, na._normalize_title("Different headline entirely"))
    assert fp_a == fp_b
    assert fp_a != fp_c


# ----------------------------------------------------------------------------
# RSS fixture parsing — exercises feedparser end-to-end without network.
# ----------------------------------------------------------------------------

def test_fetch_feed_parses_local_rss(monkeypatch):
    pytest.importorskip("feedparser")
    na = _import_agent()
    fixture = os.path.join(FIXTURES, "feed_a.xml")
    # Return the fixture bytes from any HTTP call
    class _R:
        status_code = 200
        @property
        def content(self):
            with open(fixture, "rb") as f:
                return f.read()
    monkeypatch.setattr(na.requests, "get", lambda *a, **kw: _R())
    arts = na._fetch_feed("https://example.invalid/a", "rss")
    assert len(arts) == 2
    titles = [a["title"] for a in arts]
    assert any("CVE-2099-12345" in t for t in titles)


# ----------------------------------------------------------------------------
# JSON extractor (LLM response tolerance)
# ----------------------------------------------------------------------------

def test_extract_json_plain():
    na = _import_agent()
    out = na._extract_json('{"a": 1, "b": "x"}')
    assert out == {"a": 1, "b": "x"}


def test_extract_json_with_fence():
    na = _import_agent()
    out = na._extract_json('Here you go:\n```json\n{"summary": "ok", "rce": true}\n```\n')
    assert out == {"summary": "ok", "rce": True}


def test_extract_json_with_prefix_prose():
    na = _import_agent()
    out = na._extract_json('Sure thing — {"primary_cve": "CVE-2099-12345", "rce": null}')
    assert out["primary_cve"] == "CVE-2099-12345"
    assert out["rce"] is None


def test_extract_json_returns_none_on_garbage():
    na = _import_agent()
    assert na._extract_json("not json at all") is None
    assert na._extract_json("") is None


# ----------------------------------------------------------------------------
# Boolean coercion (LLM may return "true" / "yes" / null / etc.)
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("inp,expected", [
    (True, True), (False, False), (None, None),
    ("true", True), ("True", True), ("yes", True), ("y", True),
    ("false", False), ("FALSE", False), ("no", False), ("n", False),
    ("null", None), ("UNKNOWN", None), ("", None), ("garbage", None),
])
def test_coerce_bool_or_null(inp, expected):
    na = _import_agent()
    assert na._coerce_bool_or_null(inp) is expected


# ----------------------------------------------------------------------------
# Publication date parsing (added 2026-09-10 with news_items.published_at).
#
# The feed's own date is the only thing that says how OLD a story is;
# first_seen/last_seen are ingest times. The important negative case is that an
# unparseable / absent date yields None rather than now(), which would silently
# date every undated story to its ingest time.
# ----------------------------------------------------------------------------

def test_parse_published_from_rfc822_string():
    """RSS pubDate format, which is what the real fixtures carry."""
    na = _import_agent()
    dt = na._parse_published({}, "Mon, 28 Apr 2026 10:00:00 GMT")
    assert dt is not None
    assert (dt.year, dt.month, dt.day, dt.hour) == (2026, 4, 28, 10)
    assert dt.tzinfo is not None, "must be timezone-aware or Postgres shifts it"


def test_parse_published_from_iso8601_string():
    """Atom feeds carry ISO-8601 instead."""
    na = _import_agent()
    dt = na._parse_published({}, "2026-04-28T10:00:00Z")
    assert dt is not None
    assert (dt.year, dt.month, dt.day, dt.hour) == (2026, 4, 28, 10)
    assert dt.tzinfo is not None


def test_parse_published_prefers_feedparser_struct():
    """*_parsed is already normalized by feedparser, so it wins over the raw
    string. Here the two disagree on purpose."""
    na = _import_agent()
    import time
    entry = {"published_parsed": time.struct_time((2026, 4, 28, 10, 0, 0, 0, 118, 0))}
    dt = na._parse_published(entry, "Tue, 01 Jan 2030 00:00:00 GMT")
    assert dt.year == 2026 and dt.hour == 10


def test_parse_published_none_when_absent_or_garbage():
    """None is a real answer -- 'the feed did not tell us'. It must NOT fall
    back to now(), or published_at becomes a copy of first_seen."""
    na = _import_agent()
    assert na._parse_published({}, "") is None
    assert na._parse_published({}, "last Tuesday-ish") is None
    assert na._parse_published({}, None) is None


def test_fetch_feed_extracts_published_at(monkeypatch):
    """End-to-end through the real fixture: feed_a.xml's two pubDates."""
    pytest.importorskip("feedparser")
    na = _import_agent()
    fixture = os.path.join(FIXTURES, "feed_a.xml")

    class _R:
        status_code = 200
        @property
        def content(self):
            with open(fixture, "rb") as f:
                return f.read()

    monkeypatch.setattr(na.requests, "get", lambda *a, **kw: _R())
    arts = na._fetch_feed("https://example.invalid/a", "rss")
    assert len(arts) == 2
    pubs = [a["published_at"] for a in arts]
    assert all(p is not None for p in pubs), f"pubDate not parsed: {pubs}"
    # feed_a.xml: 10:00:00 GMT and 09:00:00 GMT on 2026-04-28
    assert sorted(p.hour for p in pubs) == [9, 10]
    assert all(p.tzinfo is not None for p in pubs)
