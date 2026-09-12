"""Structure a tool's raw output, so a run can be judged.

WHY THIS EXISTS
---------------
`tool_executions.parsed_results` was NULL for every netexec run — and for most
other tools — because nothing ever computed it. `db_update_tool_execution()`
accepted it as an argument and no caller passed one.

The consequence reached all the way into the learning loop. A netexec run
against a legacy-SSH host exited **0** with a rendered Python traceback in 6,816
bytes of output; with no parser, `result_count` was unknown, the run was
"unmeasured", and it was recorded as a success that could have activated a rule
as proof the tool works.

WHAT IT IS
----------
A registry, not a parser. Each entry is a tool name and a pure function from
text to a dict. Adding a tool is one line here and one function next to the
existing `etl/parse_*.py` module for it.

A tool with no entry returns None — **not** an empty dict. "Nobody has written a
parser for this" and "the parser ran and found nothing" are different facts and
the learner acts differently on each: unknown teaches it nothing, whereas zero
results is a reason to try another tool.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("tool_output_parsers")


def _netexec(output: str, error: str = "") -> Dict[str, Any]:
    try:
        from etl.parse_netexec import parse_netexec_output
    except ImportError:  # pragma: no cover - bare import from within etl/
        from parse_netexec import parse_netexec_output
    return parse_netexec_output(f"{output}\n{error}" if error else output)


# tool name -> pure text->dict parser. Aliases are listed explicitly rather than
# normalised, because `nxc` and `netexec` are genuinely both used and a silent
# prefix match would claim tools this does not handle.
PARSERS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "netexec": _netexec,
    "nxc": _netexec,
    "crackmapexec": _netexec,   # same line format; netexec is its successor
}


def parse_for(tool: str, output: str = "", error: str = "") -> Optional[Dict[str, Any]]:
    """Structured results for this tool's output, or None if unparsed.

    Never raises: a parser defect must not fail a tool run that already
    completed, and returning None then is honest — the run really is unmeasured.
    """
    fn = PARSERS.get((tool or "").strip().lower())
    if not fn:
        return None
    if not (output or "").strip() and not (error or "").strip():
        return None
    try:
        return fn(output or "", error or "")
    except Exception as e:  # noqa: BLE001
        log.warning("parser for %s failed: %s", tool, e)
        return None


def result_count(parsed: Optional[Dict[str, Any]]) -> Optional[int]:
    """How many results a parse represents, or None when it cannot be judged.

    None propagates "unmeasured" rather than asserting zero, which is the
    distinction the learner needs: a tool nobody wrote a parser for must not be
    recorded as having found nothing.
    """
    if not isinstance(parsed, dict):
        return None
    counts = parsed.get("counts")
    if isinstance(counts, dict):
        # `productive` is the parser's own judgement about whether this run
        # achieved anything, and it is the authority — netexec prints a dozen
        # informational lines on first use, and counting those as results makes
        # an empty run look successful.
        if parsed.get("productive") is False:
            return 0
        meaningful = ("credentials", "shares", "findings", "command_output_lines",
                      "hosts", "results", "items", "vulnerabilities", "ports")
        total = sum(int(counts.get(k) or 0) for k in meaningful if k in counts)
        return total
    for key in ("findings", "results", "hosts", "credentials", "items"):
        v = parsed.get(key)
        if isinstance(v, list):
            return len(v)
    return None
