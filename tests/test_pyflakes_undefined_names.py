"""No undefined names in the hot-copied service modules.

2026-10-09: `_touch_derived_spec_outcome(cve, verified, stop_reason)` referenced
a name that did not exist in `_run_refine_poc` (the local is `_stop_reason`).
`ast.parse`, the 3.10 compile check and 130+ unit tests all passed; the
NameError fired on the last line of a 28-minute build and turned the whole run
into an HTTP 500. pyflakes catches exactly this class statically.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest pyflakes && PYTHONPATH=. python -m pytest tests/test_pyflakes_undefined_names.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pyflakes_api = pytest.importorskip("pyflakes.api")
from pyflakes.reporter import Reporter  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
FILES = ["app/rag-api/api.py", "app/rag-api/build_poc_graph.py", "app/rag-api/osint_agent.py",
         "dashboard/bff/routers/exploits.py"]


class _Collect:
    def __init__(self):
        self.lines = []

    def write(self, s):
        self.lines.append(s)

    def flush(self):
        pass


def _undefined_names(path: Path) -> list[str]:
    out, err = _Collect(), _Collect()
    pyflakes_api.check(path.read_text(encoding="utf-8"), str(path), Reporter(out, err))
    text = "".join(out.lines)
    return [ln for ln in text.splitlines() if re.search(r"undefined name", ln)]


# Known debt (RATCHET — shrink, never grow). api.py had 29 undefined-name sites
# when this guard landed: 27 bare `emit_webhook` calls in functions that never
# import it (each inside try/except, so those webhooks were silently dropped)
# and an undefined `ip` (2 refs; fixed 2026-10-09 — `_extract_discovered_facts`
# now takes `ip=`, which also made tests/test_fstring_placeholders.py green).
# Recorded in Docs/OPEN_ITEMS.md. A NEW undefined name fails by name even while
# the count is under the baseline.
# DEBT PAID 2026-10-12: all 27 were `emit_webhook` call sites missing their
# local `from webhooks import emit_webhook`, each swallowed by an enclosing
# `except` — so 21 webhook events had never once fired. Baseline lowered to 0,
# which is what makes this a ratchet rather than a permanent allowance.
BASELINE_COUNT = {"app/rag-api/api.py": 0}
BASELINE_NAMES = {}


@pytest.mark.parametrize("rel", FILES)
def test_no_undefined_names(rel):
    p = REPO / rel
    if not p.exists():
        pytest.skip(f"{rel} not present")
    bad = _undefined_names(p)
    names = {re.search(r"undefined name '([^']+)'", ln).group(1) for ln in bad if re.search(r"undefined name '([^']+)'", ln)}
    new_names = names - BASELINE_NAMES.get(rel, set())
    assert not new_names, "NEW undefined names (NameError at runtime): %s\n%s" % (sorted(new_names), "\n".join(ln for ln in bad if any(f"'{n}'" in ln for n in new_names)))
    assert len(bad) <= BASELINE_COUNT.get(rel, 0), "undefined-name count grew past the baseline (%d > %d):\n%s" % (len(bad), BASELINE_COUNT.get(rel, 0), "\n".join(bad[:30]))


def test_baseline_is_not_stale():
    """The baseline must match reality EXACTLY, in both directions.

    It used to allow a 10-slack window below the baseline, which is how 27
    fixed names could sit unnoticed. At 0 that window would also make this
    assertion vacuously true forever — a guard that cannot fail is worse than
    none (CLAUDE.md). Pin it exactly instead: raising the number fails
    test_no_undefined_names, lowering it fails here until the baseline is
    updated to match.
    """
    p = REPO / "app/rag-api/api.py"
    if not p.exists():
        pytest.skip("api.py not present")
    bad = _undefined_names(p)
    expected = BASELINE_COUNT["app/rag-api/api.py"]
    assert len(bad) == expected, (
        "api.py has %d undefined names but BASELINE_COUNT says %d — "
        "update the baseline to match (down when debt is paid, and never up "
        "without a stated reason)." % (len(bad), expected))
