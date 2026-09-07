"""A regex must not be used as a substring, and the poller must classify.

Run on demand:

    pytest tests/test_polling_status_detection.py -v

WHY THIS EXISTS
---------------
The BFF poller re-reads a scanner's payload because a scanner can answer
`status: completed` while its own result says it timed out or partially failed.
That re-read was written with regex strings and then applied with `in`:

    elif ("nmap.*timed out" in str(data).lower() or
          "service detection.*failed" in str(data).lower() or
          "phase2.*error" in str(data).lower()):
        new_status = "partial"

`.*` never appears literally, so all three were permanently False. The entire
nmap partial-detection branch was unreachable, and **every partially-failed nmap
was recorded as a clean success** — the operator saw a green scan over incomplete
data, which is worse than a visible failure.

Nothing catches this: it is valid Python, the container is healthy, and the code
reads correctly at a glance. It only shows up as scans that are never `partial`.

Sabotage check: replace a `_PARTIAL_RE.search(...)` with the old `in` form -> RED.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
POLLING = os.path.join(REPO, "dashboard", "bff", "polling.py")

#: Things that look like a regex. A string containing these and used with `in`
#: is a bug: it can only match if the metacharacter appears literally.
_REGEXY = (".*", ".+", "\\s", "\\d", "\\w", "[0-9]", "(?:", "(?i)")


def _src():
    if not os.path.exists(POLLING):
        pytest.skip("polling.py not present")
    return open(POLLING, encoding="utf-8").read()


def test_no_regex_used_as_a_substring():
    """`"a.*b" in text` is always False unless '.*' is literally present."""
    tree = ast.parse(_src())
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, ast.In):
                continue
            left = node.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str):
                if any(tok in left.value for tok in _REGEXY):
                    offenders.append((getattr(node, "lineno", "?"), left.value[:60]))
    assert not offenders, (
        "these look like regexes but are used as substrings, so they can never "
        f"match: {offenders}"
    )


def _patterns():
    """Compile the module's detection regexes without importing the BFF."""
    src = _src()
    ns = {"re": re}
    for name in ("_TIMEOUT_RE", "_CMD_TIMEOUT_RE", "_PARTIAL_RE"):
        m = re.search(rf"^{name}\s*=\s*re\.compile\((.*?)\)\s*$", src, re.M | re.S)
        assert m, f"{name} not found — this guard would pass vacuously"
        ns[name] = eval(f"re.compile({m.group(1)})", ns)   # noqa: S307 - our own source
    return ns


@pytest.mark.parametrize("text,expected", [
    ("nmap timed out during service detection", True),
    ("Service Detection failed on 3 hosts", True),
    ("phase2 error in enrichment", True),
    # Must NOT fire on a healthy scan, or every scan reads as degraded.
    ("clean run, 42 hosts up", False),
    ("scan completed successfully", False),
    ("found 12 open ports", False),
])
def test_partial_detection_classifies(text, expected):
    assert bool(_patterns()["_PARTIAL_RE"].search(text)) is expected, text


@pytest.mark.parametrize("text,expected", [
    ("connection timeout after 30s", True),
    ("the command timed out", True),
    ("all good", False),
])
def test_timeout_detection_classifies(text, expected):
    assert bool(_patterns()["_TIMEOUT_RE"].search(text)) is expected, text


def test_the_poller_actually_uses_the_patterns():
    """Compiled and never called would be the same bug with extra steps."""
    src = _src()
    for name in ("_TIMEOUT_RE", "_PARTIAL_RE"):
        assert f"{name}.search(" in src, f"{name} is compiled but never used"
