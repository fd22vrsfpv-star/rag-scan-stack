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


def _fetch_path_src() -> str:
    """The whole fetch path, not one function body.

    2026-10-16: `_fetch_feed` became a LADDER driver and the HTTP details
    moved into `_strategy_*`. Four assertions here read `_fetch_feed`'s body
    and would have failed because the code IMPROVED — the exact trap
    `tests/test_guard_style.py` ratchets against. They now read the whole
    fetch path, so they keep testing the behaviour rather than its address.
    """
    src = _src()
    tree = ast.parse(src)
    want = [n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef)
            and (n.name == "_fetch_feed" or n.name.startswith("_strategy_"))]
    assert want, "neither _fetch_feed nor any _strategy_* function exists"
    return "\n".join(ast.get_source_segment(src, n) or "" for n in want)


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
    src = _fetch_path_src()
    assert "status_code" in src, "the HTTP status is not checked"
    assert "failed: HTTP" in src, (
        "the status is checked but the reason is not retained — that is the "
        "original bug, where a RuntimeError was raised and then swallowed")


def test_the_fallback_does_not_erase_the_reason():
    """A later strategy must not turn an earlier diagnosed failure into silence.

    Structural: the driver accumulates every attempt's note and returns the
    JOIN of them, so a feed no strategy rescued still reports what each one
    said. Previously this checked that the single feedparser fallback kept
    `error`; the ladder generalises it.
    """
    fn = _func("_fetch_feed")
    appends = [n for n in ast.walk(fn)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "append"
               and isinstance(n.func.value, ast.Name)
               and n.func.value.id == "attempts"]
    assert len(appends) >= 2, (
        f"only {len(appends)} attempt(s) are recorded — a strategy that fails "
        "silently leaves the operator with no reason for the dead feed")
    joined = [n for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
              and n.func.attr == "join"
              and any(isinstance(a, ast.Name) and a.id == "attempts"
                      for a in n.args)]
    assert joined, (
        "the accumulated attempts are never returned, so the ladder diagnoses "
        "each failure and then throws the diagnosis away")


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
    src = _fetch_path_src()
    assert "Accept" in src, (
        "no Accept header is sent; GitHub's advisories.atom is among the "
        "feeds that reject a request without one")


def test_redirects_are_followed_explicitly():
    src = _fetch_path_src()
    assert "allow_redirects" in src, (
        "redirects are not handled explicitly — two sources moved and the "
        "run record could not distinguish 'moved' from 'empty'")
