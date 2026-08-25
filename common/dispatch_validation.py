"""Shared pre-dispatch validation for scan tools.

A scan reaches a tool through several paths (BFF direct dispatch, the
recommender, remote-node execution). Each has independently reinvented "is this
a sane thing to run?", and the gaps show up as runtime failures the operator
sees as opaque 500s:

  * amass handed an empty targets file  -> scope gate does open('') and refuses.
  * service_enum_cli.py --domain given two domains -> "unrecognized arguments".

This module is the single place that answers, BEFORE dispatch, two questions:

  1. Are the targets well-formed for this tool? (non-empty; right *arity*)
  2. If the tool takes ONE target per run but N were requested, how should the
     work be split? (fan-out plan)

It is deliberately pure (no I/O, no DB, no imports beyond the stdlib) so it can
run anywhere and be unit-tested exhaustively. Unknown tools are treated
permissively (arity="multi") — being too strict here would block valid scans,
the same philosophy tool_catalog.validate_recommendation uses.

Keep TOOL_SPECS in sync with:
  * node_manager remote templates (_KNOWN_SCANS `cmd` placeholders)
  * osint_runner request models (single `domain` vs `domains: List[str]`)
The agreement test tests/test_dispatch_validation.py pins the two.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# arity:
#   "single" — the tool accepts exactly one target per invocation (its CLI takes
#              --domain X or a single positional). N targets must be fanned out
#              into N runs.
#   "multi"  — the tool accepts a list/file of targets in one invocation.
# requires_targets_file:
#   the runner writes targets to a file the scope gate reads; an empty/missing
#   file makes the gate fail closed, so an empty target set must be caught here.
@dataclass(frozen=True)
class ToolSpec:
    arity: str = "multi"
    requires_targets_file: bool = False
    note: str = ""


# Only tools with a non-default constraint need an entry; everything else falls
# through to the permissive default (multi, no file requirement).
TOOL_SPECS = {
    # Single-target: template places the target via a placeholder / single CLI flag.
    "service-enum": ToolSpec("single", note="service_enum_cli.py --domain (one)"),
    "email-enum":   ToolSpec("single", note="service_enum_cli.py --domain (one)"),
    "dns-enum":     ToolSpec("single", note="service_enum_cli.py --domain (one)"),
    "golinkfinder": ToolSpec("single", note="GoLinkFinder -d {target} (one)"),
    # Multi-target tools whose scope gate reads a targets FILE (empty set == refusal).
    "amass":      ToolSpec("multi", requires_targets_file=True),
    "subfinder":  ToolSpec("multi", requires_targets_file=True),
    "dnsx":       ToolSpec("multi", requires_targets_file=True),
    "shuffledns": ToolSpec("multi", requires_targets_file=True),
    "gau":        ToolSpec("multi", requires_targets_file=True),
    "waybackurls":ToolSpec("multi", requires_targets_file=True),
}

DEFAULT_SPEC = ToolSpec()


def spec_for(tool: str) -> ToolSpec:
    return TOOL_SPECS.get((tool or "").strip().lower(), DEFAULT_SPEC)


@dataclass
class ValidationResult:
    ok: bool
    reason: Optional[str] = None
    # For a "single"-arity tool given N targets, the plan to run it N times.
    # Always present when ok is True: [[t]] for single, [[t1, t2, ...]] for multi.
    fanout: List[List[str]] = field(default_factory=list)


def _clean(targets) -> List[str]:
    if targets is None:
        return []
    if isinstance(targets, str):
        raw = targets.replace(",", "\n").splitlines()
    else:
        raw = []
        for t in targets:
            raw.extend(str(t).replace(",", "\n").splitlines())
    return [t.strip() for t in raw if t and t.strip()]


def validate_dispatch(tool: str, targets) -> ValidationResult:
    """Answer, before dispatch: can this run, and how should it be split?

    Returns ValidationResult(ok, reason, fanout). `fanout` is a list of target
    groups, one per tool invocation:
      * multi  -> a single group with every target: [[t1, t2, ...]]
      * single -> one group per target:             [[t1], [t2], ...]
    The caller runs one job per group. This turns "N domains into a one-domain
    tool" from a runtime crash into N correct jobs.
    """
    spec = spec_for(tool)
    clean = _clean(targets)

    if not clean:
        # Fail closed on an empty set: a tool whose gate reads a targets file
        # would otherwise open('') and refuse deep in the runner.
        return ValidationResult(False,
            f"{tool}: no targets provided — refusing to dispatch")

    if spec.arity == "single":
        return ValidationResult(True, fanout=[[t] for t in clean])
    return ValidationResult(True, fanout=[clean])


def plan_fanout(tool: str, targets) -> List[List[str]]:
    """Convenience: the fan-out groups, or [] when validation fails."""
    res = validate_dispatch(tool, targets)
    return res.fanout if res.ok else []
