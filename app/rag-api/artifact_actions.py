"""Derive possible follow-on actions from a raw tool artifact.

Pure functions, no database and no network, so the rules can be tested on
fixtures alone (tests/test_artifact_actions.py).

Design rules, each learned the hard way in this codebase:

* EVERY suggestion cites the exact text that triggered it. A follow-up an
  operator cannot justify is one they cannot act on, and a rule that fires on
  nothing visible is indistinguishable from a bug.
* Suggestions name a `scanner` the dispatcher actually routes (see
  `_dispatch_via_kali` / the scanner ladder in routers/assets.py) and carry a
  concrete `script`. A suggestion that cannot be executed is decoration.
* Nothing here claims an action has or has not already run — that requires
  evidence from tool_executions and is decided by the caller. Suppressing on
  assumption previously hid 63 NSE scripts that had never actually run.
* Rules are conservative about scope. They only ever propose acting on the
  artifact's own target; hosts merely *mentioned* in output (a redirect to
  twitter.com, a banner citing twiki.org) are never turned into new targets.
"""
from __future__ import annotations

import glob
import hashlib
import logging
import os
import re
from typing import Any, Dict, List, Optional

import yaml

log = logging.getLogger("artifact_actions")

# Cap on how much evidence text travels with a suggestion. Enough to justify
# the action in the UI without shipping the whole artifact back per rule.
EVIDENCE_CHARS = 240


def _snippet(text: str, match: re.Match) -> str:
    """Evidence an operator can read at a glance.

    Takes the matched line, but CENTRES the window on the match when the line is
    too long to show whole. Native JSON is usually one very long line, so
    trimming from the start showed the opening of the document and never the
    thing that actually triggered the rule.
    """
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    if end == -1:
        end = len(text)
    line = _strip_ansi(text[start:end]).strip()
    if len(line) <= EVIDENCE_CHARS:
        return line
    # Offset of the match within the (stripped) line, clamped to the line.
    rel = max(0, match.start() - start)
    half = EVIDENCE_CHARS // 2
    lo = max(0, min(rel - half, len(line) - EVIDENCE_CHARS))
    hi = lo + EVIDENCE_CHARS
    return ("…" if lo > 0 else "") + line[lo:hi].strip() + ("…" if hi < len(line) else "")


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """whatweb and friends colour their stdout; escapes make evidence unreadable."""
    return _ANSI_RE.sub("", text)


# Lines where a tool is talking about ITSELF, not about the target.
#
# crackmapexec's first run prints "Generating SSL certificate" while setting up
# its own config directory — which fired the tls_present rule and proposed a TLS
# audit of a host that had shown no TLS at all. The same class of bug once filed
# nmap.org/sqlmap.org banner URLs as discovered findings. Evidence drawn from a
# tool's own boilerplate is not evidence about the target.
_NOISE_LINE_RE = re.compile(
    r"first\s+time\s+use\s+detected"
    r"|creating\s+(?:home\s+)?(?:directory|folder)"
    r"|copying\s+default\s+configuration"
    r"|generating\s+ssl\s+certificate"
    r"|initializing\s+\w+\s+protocol"
    r"|^\s*starting\s+nmap\s+\d"
    r"|https?://(?:www\.)?(?:nmap\.org|sqlmap\.org|github\.com/\S+|"
    r"projectdiscovery\.io|morningstarsecurity\.com|portswigger\.net)"
    r"|\[\*\]\s*(?:loading|starting|initializing)\b",
    re.IGNORECASE | re.MULTILINE,
)


def strip_tool_noise(text: str) -> str:
    """Drop lines that describe the tool's own setup rather than the target."""
    return "\n".join(ln for ln in text.splitlines() if not _NOISE_LINE_RE.search(ln))


# ── Rule loading ──────────────────────────────────────────────────────────
#
# Rules live in YAML under /knowledge (a read-only bind mount), mirroring the
# existing detection-rule engine. They were previously hardcoded here, which
# meant every tweak needed a rag-api rebuild and every tool got an identical
# rule set — whatweb output and crackmapexec output were evaluated against the
# same 16 patterns whether or not they could possibly apply.
#
# Files are re-read when any of their mtimes change, so an operator can edit a
# pattern and see the effect on the next analysis without restarting anything.

RULES_DIR = os.environ.get("ARTIFACT_RULES_DIR", "/knowledge/artifact_rules")

# Fields a rule must supply. A rule missing any of these cannot produce a
# runnable, justifiable suggestion, so it is skipped loudly rather than
# half-rendered in the UI.
_REQUIRED = ("id", "pattern", "scanner", "script", "title", "rationale")

_DEFAULTS = {"priority": 50, "category": "general", "auto_queue": False,
             "enabled": True, "tools": ["*"], "needs_input": False}

# (rules, errors, signature) — signature is the set of (path, mtime) seen.
_cache: Dict[str, Any] = {"rules": None, "errors": [], "sig": None}


def _rule_files(rules_dir: str) -> List[str]:
    """builtin.yaml first, then custom/*.yaml sorted — later files override
    earlier ones by `id`, so local edits win over shipped defaults."""
    files = []
    builtin = os.path.join(rules_dir, "builtin.yaml")
    if os.path.exists(builtin):
        files.append(builtin)
    files.extend(sorted(glob.glob(os.path.join(rules_dir, "custom", "*.yaml"))))
    return files


def _signature(files: List[str]):
    """Content hash per file — deliberately not mtime.

    mtime is not reliable here: inside the container two writes to the same rule
    file report an IDENTICAL st_mtime_ns, so an edit made shortly after a load
    would never be picked up and the operator would see no effect from their
    change. Rule files are a few KB, so hashing them on each check costs
    microseconds against regex work measured in milliseconds, and it is correct
    on every filesystem.
    """
    out = []
    for f in files:
        try:
            with open(f, "rb") as fh:
                out.append((f, hashlib.sha1(fh.read()).hexdigest()))
        except OSError:
            pass
    return tuple(out)


def load_rules(rules_dir: str = None, force: bool = False):
    """Return (rules, errors). Cached until a rule file changes on disk."""
    rules_dir = rules_dir or RULES_DIR
    files = _rule_files(rules_dir)
    sig = _signature(files)
    if not force and _cache["rules"] is not None and _cache["sig"] == sig:
        return _cache["rules"], _cache["errors"]

    by_id: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    if not files:
        errors.append(f"no rule files found in {rules_dir} — no suggestions can be made")

    for path in files:
        try:
            with open(path) as fh:
                doc = yaml.safe_load(fh) or {}
        except Exception as e:
            errors.append(f"{os.path.basename(path)}: unreadable ({type(e).__name__}: {e})")
            continue
        defaults = {**_DEFAULTS, **(doc.get("defaults") or {})}
        for raw in (doc.get("rules") or []):
            if not isinstance(raw, dict):
                errors.append(f"{os.path.basename(path)}: rule is not a mapping")
                continue
            rule = {**defaults, **raw}
            missing = [k for k in _REQUIRED if not rule.get(k)]
            if missing:
                errors.append(f"{os.path.basename(path)}: rule "
                              f"{raw.get('id', '<no id>')!r} missing {', '.join(missing)}")
                continue
            try:
                rule["_rx"] = re.compile(rule["pattern"], re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                errors.append(f"{os.path.basename(path)}: rule {rule['id']!r} "
                              f"has an invalid pattern ({e})")
                continue
            tools = rule.get("tools") or ["*"]
            if isinstance(tools, str):
                tools = [tools]
            rule["tools"] = [str(t).lower() for t in tools]
            try:
                rule["priority"] = int(rule["priority"])
            except (TypeError, ValueError):
                rule["priority"] = 50
            by_id[rule["id"]] = rule          # later file wins

    rules = [r for r in by_id.values() if r.get("enabled", True)]
    _cache.update({"rules": rules, "errors": errors, "sig": sig})
    if errors:
        for e in errors:
            log.warning("artifact rule: %s", e)
    return rules, errors


def rule_applies_to_tool(rule: Dict[str, Any], tool: str) -> bool:
    """A rule with tools ["*"] (or none) applies everywhere.

    Tool scoping is what stops crackmapexec output being evaluated against web
    crawl rules and vice versa — the same 16 patterns used to run over every
    artifact regardless of what produced it.
    """
    tools = rule.get("tools") or ["*"]
    if "*" in tools:
        return True
    return (tool or "").lower() in tools


def suggest_actions(content: str, tool: str = "", target: str = "",
                    port: Optional[int] = None, service: str = "",
                    llm_result: Optional[Dict[str, Any]] = None,
                    max_actions: int = 25,
                    rules_dir: str = None) -> List[Dict[str, Any]]:
    """Return candidate follow-on actions, each citing its evidence.

    `llm_result` — when an LLM pass has already run over this artifact, any
    suggestions it recorded are merged in and marked source='llm', so the
    operator sees rule-derived and model-derived proposals in one list rather
    than two competing screens.
    """
    if not content:
        return []
    text = strip_tool_noise(_strip_ansi(content))
    out: List[Dict[str, Any]] = []

    rules, _errors = load_rules(rules_dir)
    for rule in rules:
        if not rule_applies_to_tool(rule, tool):
            continue
        m = rule["_rx"].search(text)
        if not m:
            continue
        script = rule["script"]
        # Fill what we can. Placeholders that survive are flagged rather than
        # guessed — a command with a wrong port is worse than one marked
        # incomplete, because it looks runnable.
        if "{cve}" in script:
            cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))[:5]
            script = script.replace("{cve}", " ".join(cves) if cves else "{cve}")
        if "{port}" in script:
            found = port or _first_port(text)
            script = script.replace("{port}", str(found)) if found else script
        if target:
            script = script.replace("{target}", target)
        needs_input = bool(rule.get("needs_input")) or "{" in script
        out.append({
            "id": rule["id"],
            "category": rule["category"],
            "title": rule["title"],
            "scanner": rule["scanner"],
            "script": script,
            "rationale": rule["rationale"],
            "priority": rule["priority"],
            "evidence": _snippet(text, m),
            "needs_input": needs_input,
            # An action that cannot run as written must never auto-queue,
            # whatever the rule asks for — it would sit in the queue as
            # permanently un-runnable noise.
            "auto_queue": bool(rule.get("auto_queue")) and not needs_input,
            "source": "rules",
        })

    for item in _llm_suggestions(llm_result):
        if not any(o["id"] == item["id"] for o in out):
            out.append(item)

    out.sort(key=lambda a: (-a["priority"], a["id"]))
    return out[:max_actions]


def _first_port(text: str) -> Optional[int]:
    m = re.search(r"(\d{1,5})/tcp\s+open", text) or \
        re.search(r"Discovered\s+open\s+port\s+(\d{1,5})", text)
    if m:
        try:
            p = int(m.group(1))
            return p if 0 < p < 65536 else None
        except ValueError:
            return None
    return None


def _llm_suggestions(llm_result: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalise model-proposed actions into the same shape as rule output.

    Tolerant of shape: a model may return `suggested_actions`, `follow_ups` or
    `actions`, and items may be plain strings. Anything unusable is dropped
    rather than rendered as a broken half-suggestion.
    """
    if not isinstance(llm_result, dict):
        return []
    raw = None
    for key in ("suggested_actions", "follow_ups", "actions", "next_steps"):
        if isinstance(llm_result.get(key), list):
            raw = llm_result[key]
            break
    if not raw:
        return []
    out = []
    for i, item in enumerate(raw[:10]):
        if isinstance(item, str):
            item = {"title": item}
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("action") or item.get("description")
        if not title:
            continue
        script = item.get("script") or item.get("command") or ""
        out.append({
            "id": item.get("id") or f"llm_{i}",
            "category": item.get("category", "llm"),
            "title": str(title)[:200],
            "scanner": item.get("scanner") or item.get("tool") or "",
            "script": str(script)[:500],
            "rationale": str(item.get("rationale") or item.get("why") or
                             "Proposed by LLM post-processing.")[:500],
            "priority": int(item.get("priority", 55)),
            "evidence": str(item.get("evidence", ""))[:EVIDENCE_CHARS],
            # No scanner or no command means nothing to dispatch.
            "needs_input": not (item.get("scanner") and script) or "{" in str(script),
            # Model-proposed actions are never auto-queued. They carry no
            # verified evidence and no rule author stood behind them.
            "auto_queue": False,
            "source": "llm",
        })
    return out
