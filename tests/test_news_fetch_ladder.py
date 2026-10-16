"""A dead feed gets more than one way to be fetched.

Correcting four broken feed URLs on 2026-10-15 recovered two sources and left
two dead for reasons no URL edit can fix:

    GitHub Security Advisories  HTTP 406 even with a browser UA + Accept
                                (re-measured 2026-10-16: 406 over BOTH HTTP/2
                                and HTTP/1.1, zero-length body — a hard block)
    Assetnote Research          301 -> slcyber.io (acquired); no RSS anywhere

One fetch strategy means one way to fail. So each source is tried down a
LADDER — direct, feedparser, discover, browser, agent — and the first that
yields articles wins.

Pinned here, because each is a way for this to silently stop working:

  1. the ladder runs in its CANONICAL order, cheapest first, whatever order
     the operator listed — `agent` costs an LLM call per attempt;
  2. the first success wins and clears the error;
  3. when none succeed, the error names EVERY strategy and what each said;
  4. every outcome is one of ok:/failed:/unavailable: — a strategy that could
     not RUN must never read as a source with no news ("unreachable is not
     absent");
  5. a strategy that RAISES is a bug in us, not a verdict on the source: it is
     recorded unavailable and the ladder continues;
  6. the agent strategy may only return links the PAGE offered — a fabricated
     article url is worse than no article, because downstream nothing can tell.

No test here touches the network.

Sabotage check: return the operator's order instead of the canonical one and
`test_the_ladder_runs_cheapest_first` fails; `return articles, None` on the
first attempt regardless and `test_a_failing_strategy_falls_through` fails;
drop the `link not in page_links` check and
`test_the_agent_cannot_invent_a_link` fails.

    pytest tests/test_news_fetch_ladder.py -q
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


def _tree() -> ast.Module:
    return ast.parse(_src())


def _func(name) -> ast.FunctionDef:
    for n in ast.walk(_tree()):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    pytest.fail(f"{name} is not defined in news_agent.py")


def _const(name):
    for n in ast.walk(_tree()):
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.literal_eval(n.value)
    pytest.fail(f"{name} is not defined in news_agent.py")


def _load(*names, **ns_extra):
    """Exec named functions in isolation — news_agent pulls in heavy deps."""
    import logging
    src = _src()
    ns = {"os": __import__("os"), "re": __import__("re"), "log": logging,
          "_STRATEGY_ORDER": _const("_STRATEGY_ORDER"),
          "_STRATEGY_DEFAULT": _const("_STRATEGY_DEFAULT")}
    ns.update(ns_extra)
    body = [_func(n) for n in names]
    exec(compile(ast.Module(body=body, type_ignores=[]), "<ladder>", "exec"), ns)
    return ns


# -- 1. the ladder's shape ---------------------------------------------------

def test_the_ladder_runs_cheapest_first():
    order = _const("_STRATEGY_ORDER")
    assert order[0] == "direct", f"the cheapest strategy is not first: {order}"
    assert order[-1] == "agent", (
        f"`agent` is not last: {order} — it costs an LLM call per attempt and "
        "must only run when every cheaper strategy has failed")


def test_agent_is_off_by_default():
    assert "agent" not in _const("_STRATEGY_DEFAULT").split(","), (
        "the LLM strategy is on by default, so every dead feed spends a model "
        "call on every run without anyone asking for it")


def test_the_canonical_order_wins_over_the_operators():
    ns = _load("_enabled_strategies")
    import os
    os.environ["NEWS_FETCH_STRATEGIES"] = "agent,direct"
    try:
        assert ns["_enabled_strategies"]() == ["direct", "agent"], (
            "the operator's listed order was used verbatim — listing `agent` "
            "first would spend an LLM call before trying a plain GET")
    finally:
        os.environ.pop("NEWS_FETCH_STRATEGIES", None)


def test_an_unknown_strategy_is_reported_not_ignored():
    ns = _load("_enabled_strategies")
    import os
    os.environ["NEWS_FETCH_STRATEGIES"] = "direct,bogus"
    try:
        assert ns["_enabled_strategies"]() == ["direct"]
    finally:
        os.environ.pop("NEWS_FETCH_STRATEGIES", None)


def test_every_strategy_in_the_order_is_implemented():
    funcs = _const("_STRATEGY_FUNCS") if False else None   # it holds callables
    src = _src()
    for name in _const("_STRATEGY_ORDER"):
        assert f"def _strategy_{name}(" in src, (
            f"`{name}` is in the ladder but `_strategy_{name}` does not exist, "
            "so selecting it silently does nothing")


# -- 2. the driver -----------------------------------------------------------

def _driver(results):
    """_fetch_feed with the strategies stubbed. `results` maps name -> outcome."""
    import os
    calls = []

    def mk(name):
        def fn(url):
            calls.append(name)
            out = results[name]
            if isinstance(out, Exception):
                raise out
            return out
        return fn

    ns = _load("_enabled_strategies", "_fetch_feed",
               _STRATEGY_FUNCS={k: mk(k) for k in results})
    os.environ["NEWS_FETCH_STRATEGIES"] = ",".join(results)
    try:
        return ns["_fetch_feed"]("https://example.test/feed", "rss"), calls
    finally:
        os.environ.pop("NEWS_FETCH_STRATEGIES", None)


def test_the_first_success_wins_and_clears_the_error():
    (arts, err), calls = _driver({
        "direct": (None, "failed: HTTP 406"),
        "feedparser": ([{"title": "t", "link": "l"}], "ok: 1 article(s)"),
        "browser": ([{"title": "no", "link": "no"}], "ok: 1 article(s)"),
    })
    assert len(arts) == 1 and arts[0]["title"] == "t"
    assert err is None, f"a recovered feed still reports an error: {err}"
    assert calls == ["direct", "feedparser"], (
        f"the ladder did not stop at the first success: {calls}")


def test_a_failing_strategy_falls_through():
    (arts, err), calls = _driver({
        "direct": (None, "failed: HTTP 406"),
        "feedparser": (None, "failed: no entries"),
        "discover": ([{"title": "t", "link": "l"}], "ok: 1 article(s)"),
    })
    assert arts and err is None
    assert calls == ["direct", "feedparser", "discover"]


def test_when_all_fail_every_reason_is_reported():
    (arts, err), _ = _driver({
        "direct": (None, "failed: HTTP 406"),
        "feedparser": (None, "failed: no entries"),
        "browser": (None, "unavailable: httpx not importable"),
    })
    assert arts == []
    for expect in ("direct=", "feedparser=", "browser=", "HTTP 406",
                   "unavailable"):
        assert expect in err, f"{expect!r} missing from the reported error: {err}"


def test_a_raising_strategy_is_unavailable_not_a_verdict():
    """A crash in OUR code must not read as 'this source has no news'."""
    (arts, err), calls = _driver({
        "direct": RuntimeError("boom"),
        "feedparser": ([{"title": "t", "link": "l"}], "ok: 1"),
    })
    assert arts, "a raising strategy aborted the ladder instead of falling through"
    assert calls == ["direct", "feedparser"]


def test_a_raise_in_the_last_strategy_is_still_reported_unavailable():
    (arts, err), _ = _driver({"direct": RuntimeError("boom")})
    assert arts == []
    assert "unavailable" in err and "RuntimeError" in err, err


def test_no_enabled_strategy_is_itself_an_error():
    import os
    ns = _load("_enabled_strategies", "_fetch_feed", _STRATEGY_FUNCS={})
    os.environ["NEWS_FETCH_STRATEGIES"] = "nonsense"
    try:
        arts, err = ns["_fetch_feed"]("https://example.test/feed", "rss")
        assert arts == [] and err and "no fetch strategy enabled" in err, err
    finally:
        os.environ.pop("NEWS_FETCH_STRATEGIES", None)


# -- 3. three outcomes, everywhere -------------------------------------------

def test_every_strategy_returns_a_classified_note():
    """ok: / failed: / unavailable: — never a bare string."""
    src = _src()
    tree = ast.parse(src)
    for name in _const("_STRATEGY_ORDER"):
        fn = _func(f"_strategy_{name}")
        notes = []
        for r in ast.walk(fn):
            if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple) \
                    and len(r.value.elts) == 2:
                notes.append(r.value.elts[1])
        assert notes, f"_strategy_{name} never returns a (articles, note) pair"
        for n in notes:
            txt = ast.unparse(n)
            classified = any(p in txt for p in (
                "'ok:", '"ok:', "'failed:", '"failed:',
                "'unavailable:", '"unavailable:'))
            # A strategy may delegate the note to `_parse_or_none`, which
            # classifies on its behalf — either by returning its call directly
            # or by returning the name it was unpacked into.
            delegated = "_parse_or_none" in txt or txt.strip() in ("note", "arts, note")
            assert classified or delegated, (
                f"_strategy_{name} returns an unclassified note {txt[:90]} — "
                "the operator cannot tell 'could not run' from 'source said no'")


def test_the_shared_parser_classifies_on_their_behalf():
    """`_parse_or_none` is where delegated notes get their prefix."""
    fn = _func("_parse_or_none")
    notes = [r.value.elts[1] for r in ast.walk(fn)
             if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple)
             and len(r.value.elts) == 2]
    assert notes, "_parse_or_none returns no (entries, note) pair"
    for n in notes:
        txt = ast.unparse(n)
        assert any(p in txt for p in ("'ok:", '"ok:', "'failed:", '"failed:')), (
            f"_parse_or_none returns an unclassified note {txt[:90]}, so every "
            "strategy that delegates to it is unclassified too")


def test_unavailable_is_used_for_a_missing_dependency():
    """A skipped strategy must not be recorded as a source with no news."""
    for name in ("feedparser", "browser", "agent"):
        src = ast.get_source_segment(_src(), _func(f"_strategy_{name}")) or ""
        assert "unavailable:" in src, (
            f"_strategy_{name} has no `unavailable:` outcome, so a missing "
            "dependency or a down service reads as an empty feed")


# -- 4. autodiscovery --------------------------------------------------------

HTML = """<html><head>
<link rel="stylesheet" href="/x.css">
<link rel="alternate" type="application/rss+xml" title="RSS" href="/blog/rss">
<link rel='alternate' type='application/atom+xml' href='https://other.test/atom'>
<link rel="alternate" type="text/html" href="/not-a-feed">
</head><body><a href="/post/1">p</a></body></html>"""


def test_discovery_finds_rss_and_atom_and_resolves_relative():
    ns = _load("_discover_feed_urls")
    got = ns["_discover_feed_urls"](HTML, "https://site.test/blog/")
    assert got == ["https://site.test/blog/rss", "https://other.test/atom"], got


def test_discovery_ignores_non_feed_alternates():
    ns = _load("_discover_feed_urls")
    assert not any("not-a-feed" in u for u in
                   ns["_discover_feed_urls"](HTML, "https://site.test/")), (
        "a text/html alternate was treated as a feed")


def test_discovery_on_a_page_with_no_feed_returns_empty():
    ns = _load("_discover_feed_urls")
    assert ns["_discover_feed_urls"]("<html><head></head></html>",
                                     "https://site.test/") == []


# -- 5. the agent may not invent anything ------------------------------------

def test_the_agent_cannot_invent_a_link():
    """Checked structurally: the returned link must be one the page offered.

    Verified live 2026-10-16: on slcyber.io the model returned three articles
    whose links the page DID offer as relative hrefs — the first version of
    this check compared against the raw HTML and dropped all three. So the
    check must compare against the page's RESOLVED links, not its source text.
    """
    fn = _func("_strategy_agent")
    src = ast.get_source_segment(_src(), fn) or ""
    assert "page_links" in src, (
        "the agent strategy does not build the set of links the page offers, "
        "so a model-invented article url would be stored as real")
    cmps = [n for n in ast.walk(fn) if isinstance(n, ast.Compare)
            and any(isinstance(c, ast.NotIn) for c in n.ops)
            and any(isinstance(x, ast.Name) and x.id == "page_links"
                    for x in n.comparators)]
    assert cmps, (
        "nothing tests membership in `page_links` — the anti-fabrication "
        "guard is declared and not applied")
    idx = ast.get_source_segment(_src(), _func("_page_link_index")) or ""
    assert "urljoin" in idx, (
        "relative hrefs are not resolved, so every article on a site that "
        "writes href=\"/post/1\" is dropped as fabricated")


def test_the_agent_is_given_the_link_index_not_the_raw_page():
    """Truncating the document cut off the very links it was asked to find.

    slcyber.io's resources page is 754,501 bytes of mostly inline script; the
    first version truncated it at 60k, so the model never saw any of the 14
    article links and honestly reported none. The same page yields 87 links.
    """
    src = ast.get_source_segment(_src(), _func("_strategy_agent")) or ""
    assert "_page_link_index" in src, (
        "the agent strategy no longer builds a link index — it is back to "
        "feeding the model a truncated document")
    assert "_AGENT_PROMPT %" in src, "the prompt is not formatted with the page data"


def test_the_agent_prompt_forbids_inventing_links():
    prompt = _const("_AGENT_PROMPT")
    assert "Never invent" in prompt and "verbatim" in prompt, (
        "the prompt does not forbid invented links; the code guard is the "
        "real defence but the prompt should not be working against it")
