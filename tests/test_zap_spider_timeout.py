"""Every ZAP wait loop must be bounded, or the pipeline stage hangs forever.

Run on demand:

    pytest tests/test_zap_spider_timeout.py -v

WHY THIS EXISTS
---------------
`zap_scan_with_urls(max_wait=900)` bounds only the ACTIVE scan — its own docstring
says so. Both SPIDER loops were:

    sid = zap.spider.scan(s, contextname=ctx_name)
    while int(zap.spider.status(sid)) < 100:
        time.sleep(2)

with no deadline and no iteration cap. A spider that wedges hangs the pipeline
stage for ever: the job never reaches a terminal state, the operator sees
`zap_running` indefinitely, and the concurrency slot is never released.

Observed live, not theorised: spiders held 88% and 78% across repeated samples
over 15+ minutes while two pipelines sat in `zap_running`. `_MAX_SPIDER_SEEDS` is
14, so a single bad seed strands the entire scan.

The bound is per SEED — a slow seed must not consume the budget of the 13 behind
it — and expiry stops that spider and CONTINUES, because a partial site tree still
feeds the active scan and partial results beat a hung job.

Static (ast/source) checks: no ZAP, no container, runs in CI.

Sabotage check: restore `while int(zap.spider.status(sid)) < 100:` -> RED.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")


def _src():
    if not os.path.exists(WEB_SCAN):
        pytest.skip("web_scan.py not present")
    return open(WEB_SCAN, encoding="utf-8").read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name}() not found — this guard would pass vacuously")


def test_no_unbounded_spider_wait_loops():
    """The exact shape that hung. Any `while ... spider.status(...) < 100` with no
    deadline in the condition is the bug."""
    src = _src()
    offenders = []
    for m in re.finditer(r"^\s*while .*spider\.status\(.*?\).*$", src, re.M):
        line = m.group(0)
        if not re.search(r"(deadline|time\.time\(\)|waited|max_wait|elapsed)", line):
            offenders.append(line.strip()[:90])
    assert not offenders, (
        "these spider wait loops have no deadline — a wedged spider hangs the "
        f"pipeline stage forever: {offenders}"
    )


def test_the_bounded_helper_exists_and_stops_the_spider():
    src = _src()
    assert "_await_spider" in src, "no bounded spider helper"
    body = _func(src, "_await_spider")
    assert "deadline" in body, "the helper has no deadline"
    assert "spider.stop" in body, (
        "an expired spider is abandoned but never stopped — it keeps running "
        "inside ZAP and competes with the next seed"
    )
    assert "return" in body, "the helper must report whether it finished"


def test_every_spider_call_uses_the_helper():
    src = _src()
    starts = len(re.findall(r"zap\.spider\.scan\(", src))
    awaits = len(re.findall(r"_await_spider\(", src))
    assert starts > 0, "no spider calls found — guard would pass vacuously"
    assert awaits >= starts, (
        f"{starts} spider scans started but only {awaits} bounded waits — a "
        "spider started without the helper is unbounded again"
    )


def test_the_budget_is_per_seed_not_shared():
    """A slow seed must not consume the budget of the seeds behind it."""
    src = _src()
    body = _func(src, "_await_spider")
    assert "time.time() +" in body, (
        "the deadline is not computed per call — a shared deadline means later "
        "seeds inherit an already-expired budget and are skipped entirely"
    )


def test_the_timeout_is_configurable():
    src = _src()
    assert "ZAP_SPIDER_MAX_WAIT" in src, "no env override for the spider budget"
    m = re.search(r'ZAP_SPIDER_MAX_WAIT\s*=\s*int\(os\.environ\.get\("ZAP_SPIDER_MAX_WAIT",\s*"(\d+)"\)\)', src)
    assert m, "ZAP_SPIDER_MAX_WAIT is not read from the environment with a default"
    assert 30 <= int(m.group(1)) <= 1800, \
        f"default of {m.group(1)}s is outside a sane range"


def test_url_seeding_is_bounded():
    """The blocker actually observed. `ZAPv2.urlopen` forwards kwargs to
    `requests.get`; with no timeout it blocks for ever on a URL the target never
    answers, and seeding runs BEFORE the spider — so no spider ever starts and
    the stage produces nothing at all. A pipeline logged "Running ZAP with 59
    seeded URLs" and then sat silent for 25+ minutes."""
    src = _src()
    m = re.search(r"zap\.urlopen\(([^)]*)\)", src)
    assert m, "no zap.urlopen call found — guard would pass vacuously"
    for call in re.findall(r"zap\.urlopen\(([^)]*)\)", src):
        assert "timeout" in call, (
            f"zap.urlopen({call}) has no timeout — one unanswering URL blocks "
            "seeding for ever, before any spider is started"
        )


def test_seeding_has_a_total_budget():
    """A per-URL timeout alone still allows 59 x 10s of stalling."""
    src = _src()
    assert "ZAP_SEED_BUDGET" in src, "no overall seeding budget"
    assert re.search(r"time\.time\(\)\s*>=\s*_seed_deadline", src), (
        "the seeding loop does not check a deadline, so the budget is never enforced"
    )


def test_a_skipped_seed_is_visible():
    """A silently skipped seed means the active scan never covers that URL while
    the scan still reports success."""
    src = _src()
    m = re.search(r"Failed to seed \{s\}", src)
    assert m, "the seed failure message is gone"
    line_start = src.rfind("logger.", 0, m.start())
    assert src[line_start:m.start()].startswith("logger.warning"), (
        "a failed seed is logged below warning level — it will not be noticed"
    )


def test_active_scan_stays_bounded_too():
    """The half that was already correct must not regress."""
    src = _src()
    loops = re.findall(r"^\s*while .*ascan\.status\(.*$", src, re.M)
    assert loops, "no active-scan wait loops found — guard would pass vacuously"
    for line in loops:
        assert "max_wait" in line or "waited" in line, \
            f"active-scan loop lost its bound: {line.strip()[:90]}"
