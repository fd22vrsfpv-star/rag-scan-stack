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
import os
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


# ── The extractor specs, as a second tier of parser ────────────────────────
#
# knowledge/extractors/*.yaml already describes how to read fourteen tools, as
# named regexes over their output. Those specs are authored through the
# Extract & Learn surface from real captured output, which is exactly the
# "create a parser" path — so a tool with a spec is a tool with a parser, and
# wiring them in here is what makes authoring one actually close the gap.
#
# This APPLIES a spec; it does not author one. Authoring lives in
# app/rag-api/extractor_learn.py and is unchanged. The two implementations of
# "run the deterministic patterns" are pinned to each other by
# tests/test_post_enumeration.py::test_the_two_spec_runners_agree, because a
# duplicated rule that drifts is worse than one that was never shared.

SPEC_DIR = os.environ.get("EXTRACTOR_SPEC_DIR", "/knowledge/extractors")
_SPEC_CACHE: Dict[str, Optional[Dict[str, Any]]] = {}


def _spec_for(tool: str) -> Optional[Dict[str, Any]]:
    """The extractor spec for a tool, honouring `aliases:`."""
    tool = (tool or "").strip().lower()
    if not tool:
        return None
    if tool in _SPEC_CACHE:
        return _SPEC_CACHE[tool]
    found = None
    try:
        import yaml
        if os.path.isdir(SPEC_DIR):
            for fn in sorted(os.listdir(SPEC_DIR)):
                if not fn.endswith((".yaml", ".yml")) or fn.startswith("_"):
                    continue
                with open(os.path.join(SPEC_DIR, fn), encoding="utf-8") as fh:
                    spec = yaml.safe_load(fh) or {}
                names = [str(spec.get("tool") or "").lower()]
                names += [str(a).lower() for a in (spec.get("aliases") or [])]
                if tool in names and spec.get("enabled", True):
                    found = spec
                    break
    except Exception as e:  # noqa: BLE001
        log.debug("extractor spec lookup for %s failed: %s", tool, e)
    _SPEC_CACHE[tool] = found
    return found


def _from_spec(tool: str, output: str, error: str = "") -> Optional[Dict[str, Any]]:
    """Run a spec's deterministic patterns over the output."""
    import re as _re
    spec = _spec_for(tool)
    if not spec:
        return None
    text = f"{output}\n{error}" if error else output
    fields: Dict[str, Any] = {}
    for name, decl in (spec.get("deterministic") or {}).items():
        pattern = decl.get("pattern") if isinstance(decl, dict) else decl
        if not pattern:
            continue
        try:
            m = _re.search(pattern, text, _re.M | _re.I)
        except _re.error:
            continue
        if m:
            fields[name] = m.group(1) if m.groups() else m.group(0)
    return {
        "tool": tool, "parser": "extractor_spec",
        "spec": spec.get("tool"),
        "extracted": fields,
        "counts": {"fields": len(fields)},
        # A spec that matched nothing read the output and found nothing, which
        # is a measurement. That is the whole difference from having no parser.
        "productive": bool(fields),
    }


def parse_status(tool: str) -> Dict[str, Any]:
    """Whether this tool can be read at all, and by what.

    ``{"tool", "has_parser", "kind"}`` where kind is `registry`, `extractor` or
    None. The distinction is the point: "no parser exists for this tool" is a
    DIFFERENT state from "the parser found nothing", it is actionable in a way
    the other is not, and until now it was invisible.
    """
    name = (tool or "").strip().lower()
    if name in PARSERS:
        return {"tool": name, "has_parser": True, "kind": "registry"}
    if _spec_for(name):
        return {"tool": name, "has_parser": True, "kind": "extractor"}
    return {"tool": name, "has_parser": False, "kind": None}


def parse_for(tool: str, output: str = "", error: str = "") -> Optional[Dict[str, Any]]:
    """Structured results for this tool's output, or None if unparsed.

    Never raises: a parser defect must not fail a tool run that already
    completed, and returning None then is honest — the run really is unmeasured.
    """
    if not (output or "").strip() and not (error or "").strip():
        return None
    fn = PARSERS.get((tool or "").strip().lower())
    if fn:
        try:
            return fn(output or "", error or "")
        except Exception as e:  # noqa: BLE001
            log.warning("parser for %s failed: %s", tool, e)
            return None
    # Second tier: an extractor spec. Authoring one through Extract & Learn is
    # the supported way to close a parser gap, so a spec has to count as a
    # parser or authoring one would change nothing.
    return _from_spec(tool, output or "", error or "")


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
