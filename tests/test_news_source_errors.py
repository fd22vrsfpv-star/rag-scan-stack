"""A news source that fetched nothing must say WHY.

`_fetch_feed` checked the HTTP status and then threw the answer away:

    if resp.status_code >= 400:
        raise RuntimeError(f"http {resp.status_code}")
    ...
    except Exception:
        feed = feedparser.parse(url)      # fails quietly, yields nothing

So a blocked or moved feed produced `articles: 0, error: None` — identical in
the run record to a feed that genuinely had nothing new. Four of seventeen
sources were in that state, and the operator's reasonable read of the panel
("the news isn't loading") was closer to the truth than the record was.

CLAUDE.md: "`except: pass` around an HTTP call hides a 404 forever. If a call
may legitimately fail, handle that case explicitly and surface it. Silence here
turns a broken endpoint into 'it returned zero results'."

With the error recorded, the four silent zeros became four diagnosable faults
in one run, and two were immediately fixable:

    GitHub Security Advisories  HTTP 406  — blocked, disabled
    Microsoft MSRC              301 -> HTML; moved to api.msrc.microsoft.com  FIXED
    Assetnote Research          301 -> slcyber.io (acquired); no feed  disabled
    CSO Online                  HTTP 404; moved to /feed/                     FIXED

Sabotage check: restore the bare `except Exception:` fallback and
`test_a_failed_fetch_returns_a_reason` fails; drop the caller's assignment and
`test_the_caller_records_the_error` fails.

    pytest tests/test_news_source_errors.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
AGENT = REPO / "news_runner" / "news_agent.py"


def _src() -> str:
    if not AGENT.exists():
        pytest.skip("news_agent.py not found")
    return AGENT.read_text(encoding="utf-8")


def _func(name):
    for n in ast.walk(ast.parse(_src())):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} is not defined in news_agent.py")


def test_a_failed_fetch_returns_a_reason():
    """The fetcher must hand back WHY, not just an empty list."""
    fn = _func("_fetch_feed")
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert returns, "_fetch_feed has no return"
    for r in returns:
        assert isinstance(r.value, ast.Tuple) and len(r.value.elts) == 2, (
            "_fetch_feed returns a bare list again, so a blocked or moved feed "
            "is indistinguishable from one that had nothing new")


def test_the_status_code_is_checked_and_kept():
    src = ast.get_source_segment(_src(), _func("_fetch_feed")) or ""
    assert "status_code" in src, "the HTTP status is not checked"
    assert "error =" in src, (
        "the status is checked but the reason is not retained — that is the "
        "original bug, where a RuntimeError was raised and then swallowed")


def test_the_fallback_does_not_erase_the_reason():
    """The feedparser fallback must not turn a diagnosed failure into silence."""
    src = ast.get_source_segment(_src(), _func("_fetch_feed")) or ""
    i = src.find("feedparser.parse(url)")
    assert i > 0, "the fallback path is gone"
    tail = src[i:]
    assert "error" in tail, (
        "the fallback discards the original error, so a feed it fails to "
        "rescue reports nothing about why the primary fetch failed")


def test_the_caller_records_the_error():
    fn = _func("fetch_all_sources") if any(
        isinstance(n, ast.FunctionDef) and n.name == "fetch_all_sources"
        for n in ast.walk(ast.parse(_src()))) else None
    src = _src()
    assert "fetch_error" in src, (
        "the caller does not unpack the fetcher's error, so it never reaches "
        "news_runs.per_source where an operator would see it")
    # Structural: an assignment into src_stats["error"] whose value is the
    # unpacked fetch_error. A substring window matched the same text in the
    # dict literal that initialises the record to None.
    tree = ast.parse(src)
    wrote = False
    for n in ast.walk(tree):
        if not isinstance(n, ast.Assign):
            continue
        for t in n.targets:
            if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                    and t.value.id == "src_stats"
                    and isinstance(t.slice, ast.Constant) and t.slice.value == "error"
                    and isinstance(n.value, ast.Name) and n.value.id == "fetch_error"):
                wrote = True
    assert wrote, (
        "the error is unpacked but never assigned to src_stats['error'], so "
        "it never reaches news_runs.per_source where an operator would see it")


def test_one_dead_feed_does_not_abort_the_run():
    """Sixteen working sources must not be lost to one broken one.

    Checked on the AST. A substring search for "raise" matched the word
    "raised" in the comment explaining that the error is NOT raised — the
    fifth time in a day that a prose mention satisfied an assertion about
    code.
    """
    tree = ast.parse(_src())
    for node in ast.walk(tree):
        # the `if fetch_error:` branch
        if not isinstance(node, ast.If):
            continue
        if not any(isinstance(n, ast.Name) and n.id == "fetch_error"
                   for n in ast.walk(node.test)):
            continue
        raises = [n for n in ast.walk(node) if isinstance(n, ast.Raise)]
        assert not raises, (
            f"the fetch-error branch raises (line {raises[0].lineno}); one "
            "dead feed would abort the whole ingest instead of being recorded")
        return
    pytest.fail("no `if fetch_error:` branch found — the error is not handled")


def test_an_accept_header_is_sent():
    """Several feeds refuse a request that does not say it wants a feed."""
    src = ast.get_source_segment(_src(), _func("_fetch_feed")) or ""
    assert "Accept" in src, (
        "no Accept header is sent; GitHub's advisories.atom is among the "
        "feeds that reject a request without one")


def test_redirects_are_followed_explicitly():
    src = ast.get_source_segment(_src(), _func("_fetch_feed")) or ""
    assert "allow_redirects" in src, (
        "redirects are not handled explicitly — two sources moved and the "
        "run record could not distinguish 'moved' from 'empty'")
