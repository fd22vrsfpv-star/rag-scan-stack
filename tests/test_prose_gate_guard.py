"""Ratchet: a gate may not BLOCK on a substring match over prose.

    pytest tests/test_prose_gate_guard.py -v
    python tests/test_prose_gate_guard.py        # report every hit, no pytest

WHAT WENT WRONG (four instances, all 2026-10-17, one class)
-----------------------------------------------------------
`_assess_exploit_readiness` decided whether an exploit needs a session with

    if any(k in pre_blob for k in ("auth", "login", "session", ...)):
        blockers.append("exploit requires authentication but NO session ...")

The literal ``"auth"`` is a substring of **"pre-authentication"** and of
**"unauthenticated"** — the two phrases that mean the exact opposite, that NO
session is needed. On a six-case table the bare test was wrong on three, every
one of them in the blocking direction, and CVE-2026-21589 stopped at
``gather_incomplete:auth`` with **0 iterations** twice, for a flaw whose
defining property is needing no auth. Three siblings the same day: ``\\bsql\\b``
matching inside ``/phpmyadmin/sql.php`` because ``\\b`` treats ``/`` and ``.``
as word boundaries; a CWE-918 SSRF advisory classified ``sqli`` because its
prose happened to mention an SQL error; endpoint selection taking the first
non-404 so a 302 beat an unprobed 200.

Each was fixed individually. The CLASS was not, which is why it kept coming
back — and the failure mode is silent, because a gate that matched the wrong
words looks identical to a gate that found nothing.

THE RULE THIS ENFORCES
----------------------
No gate reaches a block/allow decision from a substring test over PROSE
(description / preconditions / advisory / summary text) unless the same
decision also consults an OBSERVATION — a probe, a ``.status_code``, a
``confirmed_facts`` lookup, or an already-gathered fact.

Corroboration is scoped to the DECISION, never to the function. "This function
contains a ``.status_code`` somewhere" is the co-occurrence trap that makes a
guard pass while the bug is live: the observation has to be in the `if` test
itself, in the expression that defines the name the test reads, or in a nested
condition that dominates the blocking action. ``_gather_manifest``'s auth item
is the model — it probes the session and branches on what the probe SAW.

The fixed shape is `_auth_requirement(pre_blob, desc) -> (needs, matched, why)`:
a verdict that carries the phrase that decided it, so a wrong match is visible
instead of silent. A bare `k in blob` carries nothing.

WHAT IS NOT A PROSE GATE
------------------------
  * ``if status not in valid_statuses: raise HTTPException`` — enum validation.
    The unknown is on the LEFT and the container on the RIGHT; nothing is being
    read out of prose.
  * ``if "error" in stdout`` / ``in command`` / ``in resp.text`` — a substring
    test over an OUTPUT or a COMMAND is an observation, which is the thing this
    guard is asking for.
  * computing a LABEL (``vuln_class = "sqli"``). Wrong labels hurt, but this
    guard is about the decision to block, allow, refuse or raise.

RATCHET
-------
`PROSE_GATE_DEBT` lists the gates that violate this today, each with a reason.
A NEW one fails by name. A resolved one must be DELETED — a separate test
fails on a stale entry, so the list cannot quietly become fiction.

It ships with ONE entry, because the four known instances were fixed before
this guard was written and the sweep then found a fifth nobody had looked at:
the version-applicability clause. The other six prose probes that reach a gate
action in live code are corroborated and are pinned by
`test_detector_reaches_live_gate_code`, so "the list is short" can never
silently mean "the detector stopped reaching the code". Reverting
`_assess_exploit_readiness` to its pre-fix `any(k in pre_blob ...)` makes this
file fail by name — verified.
"""
import ast
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Roots scanned. app/rag-api holds the build-PoC gates where all four
# instances landed; etl/ holds the deterministic rules engine and the
# proxy/scope helpers the OPEN_ITEMS entry also names; the rest are the
# services that decide whether something runs.
_ROOTS = ("app", "etl", "dashboard/bff", "exploit_runner", "autogen_agents",
          "scan_recommender", "kali_listener", "node_manager")


def _scanned_files():
    for root in _ROOTS:
        base = os.path.join(REPO, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames
                           if d not in {"__pycache__", "node_modules", ".git",
                                        "tests", "migrations"}]
            for fn in sorted(filenames):
                if fn.endswith(".py"):
                    full = os.path.join(dirpath, fn)
                    yield os.path.relpath(full, REPO).replace(os.sep, "/"), full


# The file every instance was found in; named so the sweep cannot go vacuous
# by quietly scanning nothing.
ANCHOR_FILE = "app/rag-api/api.py"


# ── vocabulary ────────────────────────────────────────────────────────────
#
# Matching is on identifier SEGMENTS (`pre_blob` -> {"pre", "blob"}), not on
# raw substrings, because raw substrings are the very bug this guard exists to
# catch: "facts" is a substring of "artifacts" and "auth" of "unauthenticated".

# A name holding human prose about a vulnerability.
_PROSE_SEG = {
    "desc", "descr", "description", "descriptions", "advisory", "advisories",
    "precond", "preconds", "precondition", "preconditions", "summary",
    "writeup", "rationale", "guidance", "prose", "notes", "note",
    "explanation", "overview", "abstract", "remediation", "narrative",
    "blurb", "blob", "research", "text", "details", "detail", "analysis",
    "impact", "solution", "synopsis", "advice",
}
# A segment that makes the name an OBSERVATION or a LOCATOR, not prose. These
# win over _PROSE_SEG: `resp_text` and `output_text` are what the target said.
_NOT_PROSE_SEG = {
    "resp", "response", "output", "out", "stdout", "stderr", "body", "html",
    "cmd", "command", "payload", "banner", "raw", "url", "path", "header",
    "headers", "json", "row", "rows", "tool", "args", "content", "page",
    "stdouterr", "result", "results", "log", "logs",
}
# dict keys / subscripts that source prose.
_PROSE_KEY = {
    "description", "summary", "preconditions", "advisory", "advisory_text",
    "notes", "remediation", "writeup", "rationale", "guidance", "research",
    "explanation", "impact", "solution", "synopsis", "details", "reasoning",
    "narrative", "advice",
}

# An observation: something the target, the probe or the fact store SAID.
_OBS_SEG = {
    "observed", "probe", "probed", "reachable", "measured", "resolved",
    "gathered", "facts", "fact", "evidence", "fetched", "confirmed",
}
_OBS_SUBSTR = ("status_code", "http_status", "precond_result", "probe_result",
               "confirmed_fact")
# callee names that perform an observation.
_OBS_CALL_SUBSTR = ("probe", "fetch", "reachab", "measure", "observe",
                    "verify", "http_get", "http_head", "request", "_head",
                    "status_of", "check_live", "resolve_fact", "confirmed_fact")
_SQL_VERB = ("select", "insert", "update", "delete", "from ")

# Lists an item is appended to when it is BLOCKED.
_BLOCK_LIST_SEG = {"blocker", "blockers", "missing", "unmet", "refusals",
                   "refused", "denied", "blocked", "rejections", "violations",
                   "problems"}
# Lists an item is appended to when it is CLEARED. The allow direction is the
# same defect: `satisfied.append(...)` / `confirmed.append(...)` from a
# substring match records a prose CLAIM as a settled fact, which is how an
# advisory-derived guess ends up standing in for a probe.
# Deliberately NOT "proven"/"verified"/"passed": `proven_lines.append(...)` in
# _recon_strategist assembles a PROMPT section out of an already-probed WAF
# characterisation. It decides nothing, and counting it would have put two
# false entries in the debt list on this guard's first run.
_ALLOW_LIST_SEG = {"satisfied", "confirmed", "cleared", "allowed", "approved"}
# Status strings that mean "this did not pass".
_GATE_STATUS = {"missing", "blocked", "refused", "denied", "not_ready",
                "unmet", "rejected", "unavailable"}
# `ready = False`, `allowed = False`, ...
_FALSE_TARGET_SEG = {"ready", "allowed", "approved", "permitted", "runnable",
                     "eligible", "ok", "safe", "authorized", "authorised"}
# `version_unconfirmed = False` — clearing a doubt is an allow decision.
_CLEARING_TARGET_SEG = {"unconfirmed", "unmet", "unverified", "blocked",
                        "missing", "unresolved", "unknown"}


def _segments(name):
    return set(s for s in re.split(r"[^a-z0-9]+", (name or "").lower()) if s)


def _is_prose_name(name):
    segs = _segments(name)
    if segs & _NOT_PROSE_SEG:
        return False
    return bool(segs & _PROSE_SEG)


def _is_obs_name(name):
    low = (name or "").lower()
    if any(s in low for s in _OBS_SUBSTR):
        return True
    return bool(_segments(name) & _OBS_SEG)


def _callee(node):
    f = getattr(node, "func", None)
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


def _base_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


# ── prose sources ─────────────────────────────────────────────────────────

_CONTAINER = (ast.List, ast.Set, ast.Dict, ast.Tuple, ast.ListComp,
              ast.SetComp, ast.DictComp)


def _keys_read(node):
    """Every constant dict key this expression reads: `x.get("k")`, `x["k"]`."""
    keys = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                and sub.func.attr == "get" and sub.args:
            a = sub.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                keys.append(a.value.lower())
        if isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant) \
                and isinstance(sub.slice.value, str):
            keys.append(sub.slice.value.lower())
    return keys


def _reads_prose_key(node):
    """`x.get("description")` / `x["summary"]` anywhere in this expression."""
    return any(k in _PROSE_KEY for k in _keys_read(node))


def _reads_only_nonprose_keys(node):
    """Pulls named fields out of a dict, none of which is prose.

    This is the override that keeps `tep = (a.get("target_endpoint") or "")`
    from inheriting prose-ness just because `a` is the analysis dict. A
    `target_endpoint` is a LOCATOR; `a["summary"]` is prose. Without it the
    detector flags the endpoint-placeholder check, which is a false positive of
    exactly the kind this guard is supposed to be careful about.
    """
    keys = _keys_read(node)
    return bool(keys) and not any(k in _PROSE_KEY for k in keys)


class _Scope:
    """One function body: which names hold prose, which hold observations."""

    def __init__(self, fn):
        self.fn = fn
        self.assign = {}          # name -> [value expr, ...]
        self.tuple_assign = {}    # name -> [value expr, ...] for `a, b = f()`
        args = fn.args
        self.params = [a.arg for a in list(args.args) + list(args.kwonlyargs)
                       + list(args.posonlyargs)]
        if args.vararg:
            self.params.append(args.vararg.arg)
        if args.kwarg:
            self.params.append(args.kwarg.arg)
        for sub in self._own_nodes():
            if isinstance(sub, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                for t in targets:
                    if sub.value is None:
                        continue
                    if isinstance(t, ast.Name):
                        self.assign.setdefault(t.id, []).append(sub.value)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for el in t.elts:
                            if isinstance(el, ast.Name):
                                self.tuple_assign.setdefault(el.id, []).append(sub.value)
        self.prose = self._prose_names()

    def _own_nodes(self):
        """Nodes of this function, not of functions nested inside it."""
        out = []
        stack = list(self.fn.body)
        while stack:
            n = stack.pop()
            out.append(n)
            for child in ast.iter_child_nodes(n):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                      ast.Lambda, ast.ClassDef)):
                    continue
                stack.append(child)
        return out

    def _prose_names(self):
        names = {p for p in self.params if _is_prose_name(p)}
        # two passes so `blob = desc.lower()` picks `desc` up whichever order
        # the assignments appear in.
        for _ in range(2):
            for nm, vals in self.assign.items():
                if nm in names or _is_obs_name(nm):
                    continue
                if _is_prose_name(nm):
                    names.add(nm)
                    continue
                for v in vals:
                    if isinstance(v, _CONTAINER):
                        continue
                    if _reads_prose_key(v):
                        names.add(nm)
                        break
                    if _reads_only_nonprose_keys(v):
                        break
                    if any(isinstance(s, ast.Name) and s.id in names
                           for s in ast.walk(v)):
                        names.add(nm)
                        break
        return names

    def is_prose_expr(self, node):
        """Is this expression a prose BLOB (a haystack of human text)?"""
        nm = _base_name(node)
        if nm is not None:
            if _is_obs_name(nm):
                return False
            if nm in self.prose:
                return True
            for v in self.assign.get(nm, []):
                if isinstance(v, _CONTAINER):
                    return False
            return False
        return _reads_prose_key(node)


# ── the prose substring probe ─────────────────────────────────────────────

def _prose_probes(expr, scope):
    """(needle, haystack-source) for every substring probe into prose.

    Shapes: `"lit" in prose`, `k in prose` (k a loop/iter name),
    `prose.startswith("lit")`, `re.search("lit", prose)`.
    """
    found = []
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Compare) and len(sub.ops) == 1 \
                and isinstance(sub.ops[0], (ast.In, ast.NotIn)):
            hay = sub.comparators[0]
            if not scope.is_prose_expr(hay):
                continue
            left = sub.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str):
                found.append((repr(left.value), ast.unparse(hay)[:40]))
            elif isinstance(left, ast.Name):
                found.append((f"<{left.id}>", ast.unparse(hay)[:40]))
        elif isinstance(sub, ast.Call):
            attr = sub.func.attr if isinstance(sub.func, ast.Attribute) else ""
            if attr in ("startswith", "endswith", "find", "count", "index"):
                if sub.args and isinstance(sub.args[0], ast.Constant) \
                        and scope.is_prose_expr(sub.func.value):
                    found.append((f".{attr}({sub.args[0].value!r})",
                                  ast.unparse(sub.func.value)[:40]))
            elif attr in ("search", "match", "fullmatch", "findall") and len(sub.args) >= 2:
                if scope.is_prose_expr(sub.args[1]):
                    pat = sub.args[0]
                    pv = pat.value if isinstance(pat, ast.Constant) else "<expr>"
                    found.append((f"re.{attr}({str(pv)[:30]!r})",
                                  ast.unparse(sub.args[1])[:40]))
    return found


# ── observations ──────────────────────────────────────────────────────────

def _observation_in(nodes):
    """An OBSERVATION read inside these expressions/statements, or None.

    Deliberately NOT satisfied by the bare word "confirmed" in a comment or a
    docstring (those are not AST Constants in an expression position we walk),
    nor by the table name `confirmed_facts` on its own — it must appear in
    something shaped like a query.
    """
    for top in nodes:
        if top is None:
            continue
        for sub in ast.walk(top):
            if isinstance(sub, ast.Attribute) and sub.attr == "status_code":
                return "reads .status_code"
            if isinstance(sub, ast.Attribute) and sub.attr in ("fetchone", "fetchall"):
                return f"reads cursor .{sub.attr}()"
            if isinstance(sub, ast.Call):
                cal = _callee(sub).lower()
                if any(t in cal for t in _OBS_CALL_SUBSTR):
                    return f"calls {_callee(sub)}()"
            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                low = sub.value.lower()
                if "confirmed_facts" in low and any(v in low for v in _SQL_VERB):
                    return "queries confirmed_facts"
            if isinstance(sub, ast.Name) and _is_obs_name(sub.id):
                return f"reads {sub.id}"
            if isinstance(sub, ast.Attribute) and _is_obs_name(sub.attr):
                return f"reads .{sub.attr}"
    return None


# ── gate actions ──────────────────────────────────────────────────────────

def _is_gate_action(node):
    """Does this statement/expression BLOCK, refuse or mark something missing?"""
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in ("append", "extend"):
            bn = _base_name(f.value)
            if bn and _segments(bn) & _BLOCK_LIST_SEG:
                return f"{bn}.{f.attr}(...)"
            if bn and _segments(bn) & _ALLOW_LIST_SEG:
                return f"{bn}.{f.attr}(...)  [allow]"
        lits = [a.value for a in list(node.args)
                + [k.value for k in node.keywords]
                if isinstance(a, ast.Constant) and isinstance(a.value, str)]
        bad = [v for v in lits if v in _GATE_STATUS]
        if bad:
            return f"{_callee(node)}(... {bad[0]!r} ...)"
    if isinstance(node, ast.Assign):
        for t in node.targets:
            tn = _base_name(t)
            if tn is None:
                continue
            v = node.value
            if isinstance(v, ast.Constant) and v.value is False \
                    and _segments(tn) & _FALSE_TARGET_SEG:
                return f"{tn} = False"
            if isinstance(v, ast.Constant) and v.value is False \
                    and _segments(tn) & _CLEARING_TARGET_SEG:
                return f"{tn} = False  [allow]"
            if isinstance(v, ast.Constant) and v.value is True \
                    and _segments(tn) & _FALSE_TARGET_SEG:
                return f"{tn} = True  [allow]"
            if isinstance(v, ast.Constant) and isinstance(v.value, str) \
                    and v.value in _GATE_STATUS:
                return f"{tn} = {v.value!r}"
    if isinstance(node, ast.Raise):
        nm = _callee(node.exc) if isinstance(node.exc, ast.Call) else _base_name(node.exc)
        if nm and "HTTPException" in nm:
            return "raise HTTPException"
    if isinstance(node, ast.Return) and node.value is not None:
        for c in ast.walk(node.value):
            if isinstance(c, ast.Constant) and isinstance(c.value, str) \
                    and c.value in _GATE_STATUS:
                return f"return ... {c.value!r} ..."
        if isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                        and _segments(k.value) & _FALSE_TARGET_SEG \
                        and isinstance(v, ast.Constant) and v.value is False:
                    return f"return {{{k.value!r}: False}}"
    return None


def _guarded_gate_actions(stmts, guards):
    """Yield (action-description, [guard tests dominating it]).

    Walks statements, carrying the chain of `if` tests that must hold for the
    action to run. That chain is what makes corroboration DECISION-scoped: a
    `.status_code` read in a sibling branch does not corroborate this one.
    """
    out = []
    for st in stmts:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(st, ast.If):
            out += _guarded_gate_actions(st.body, guards + [st.test])
            out += _guarded_gate_actions(st.orelse, guards + [st.test])
            continue
        if isinstance(st, (ast.For, ast.AsyncFor, ast.While, ast.With,
                           ast.AsyncWith, ast.Try)):
            inner = []
            for field in ("body", "orelse", "finalbody"):
                inner += getattr(st, field, []) or []
            for h in getattr(st, "handlers", []) or []:
                inner += h.body
            out += _guarded_gate_actions(inner, guards)
            continue
        for sub in ast.walk(st):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            kind = _is_gate_action(sub)
            if kind:
                out.append((kind, guards))
    return out


# ── the detector ──────────────────────────────────────────────────────────

def _iter_functions(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def find_prose_gates(src, rel="<src>", include_corroborated=False):
    """Every block/allow decision reached from a prose substring test.

    Returns [{file, func, line, probe, haystack, action, corroborated}] — one
    entry per (decision, gate action) pair. With the default
    `include_corroborated=False` only the UNcorroborated ones come back, which
    is what the ratchet asserts on; True returns the candidates as well, so a
    test can prove the detector still reaches real code before corroboration
    clears it.
    """
    hits = []
    tree = ast.parse(src)
    for fn in _iter_functions(tree):
        scope = _Scope(fn)
        if not scope.prose and not any(
                _reads_prose_key(v) for vs in scope.assign.values() for v in vs):
            continue
        # names whose DEFINING expression is itself a prose probe
        derived = {}
        for nm, vals in scope.assign.items():
            for v in vals:
                p = _prose_probes(v, scope)
                if p:
                    derived.setdefault(nm, []).append((v, p))

        def _resolved(exprs):
            """Guard expressions plus what defines the names they read.

            `valid, why = _probe_session_valid(...)` then `if valid:` has the
            observation one hop away; without this hop the probe-confirmed leg
            of the real auth gate would be reported as uncorroborated.
            """
            out = list(exprs)
            for e in exprs:
                if e is None:
                    continue
                for sub in ast.walk(e):
                    if isinstance(sub, ast.Name):
                        out += scope.assign.get(sub.id, [])
                        out += scope.tuple_assign.get(sub.id, [])
            return out

        for node in ast.walk(fn):
            if isinstance(node, ast.IfExp):
                # `status = "missing" if "auth" in blob else "gathered"`
                probes = list(_prose_probes(node.test, scope))
                if not probes:
                    continue
                picks = [b for b in (node.body, node.orelse)
                         if isinstance(b, ast.Constant) and b.value in _GATE_STATUS]
                if not picks:
                    continue
                hits.append({
                    "file": rel, "func": fn.name, "line": node.lineno,
                    "probe": probes[0][0], "haystack": probes[0][1],
                    "action": f"ternary -> {picks[0].value!r}",
                    "corroborated": _observation_in(_resolved([node.test])),
                })
                continue
            if not isinstance(node, ast.If):
                continue
            probes = list(_prose_probes(node.test, scope))
            defining = []
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Name) and sub.id in derived:
                    for v, p in derived[sub.id]:
                        probes += p
                        defining.append(v)
            if not probes:
                continue
            actions = (_guarded_gate_actions(node.body, [])
                       + _guarded_gate_actions(node.orelse, []))
            if not actions:
                continue
            # (a) the decision's own test, (b) the expression that defines the
            # name it reads. Both corroborate every action under this `if`.
            outer = _observation_in(_resolved([node.test] + defining))
            for kind, guards in actions:
                # (c) a nested condition that DOMINATES this action.
                hits.append({
                    "file": rel, "func": fn.name, "line": node.lineno,
                    "probe": probes[0][0], "haystack": probes[0][1],
                    "action": kind,
                    # `outer` is checked first so the cheaper, stronger
                    # evidence is what gets reported.
                    "corroborated": outer or _observation_in(_resolved(guards)),
                })
    # One entry per (file, func, line, action). An UNcorroborated action wins
    # the slot: `if needs_auth:` had one leg that probed and one that did not,
    # and collapsing them the other way would hide the leg that blocks blind.
    best = {}
    for h in hits:
        key = (h["file"], h["func"], h["line"], h["action"])
        prev = best.get(key)
        if prev is None or (prev["corroborated"] and not h["corroborated"]):
            best[key] = h
    uniq = list(best.values())
    if include_corroborated:
        return uniq
    return [h for h in uniq if not h["corroborated"]]


def _scan_repo(include_corroborated=False):
    out = []
    for rel, path in _scanned_files():
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:                                    # pragma: no cover
            continue
        try:
            out += find_prose_gates(src, rel, include_corroborated)
        except SyntaxError:                                # pragma: no cover
            continue
    return out


# ── known debt ────────────────────────────────────────────────────────────
#
# Gates that reach a block decision from prose with no observation beside it.
# Each entry is (file, function) -> why it is tolerated TODAY. Shrink this.
# A new violation fails by name; a fixed one must be DELETED, not left here.

# The key is (file, function), matching SCOPE_DEBT in
# tests/test_dispatch_invariants.py. It is coarse on purpose — a second
# violation in an already-listed function will not fail by name — so prefer
# fixing an entry to extending its reason.
#
# The sweep finds 8 prose probes that reach a gate action in live code; 6 are
# corroborated and listed in the comment above `test_detector_reaches_live_gate_code`.
# These are the two that are not.

PROSE_GATE_DEBT = {
    ("app/rag-api/api.py", "_assess_exploit_readiness"):
        "Section 5, VERSION APPLICABILITY (line ~41007): `if adv and version "
        "in adv:` appends to `satisfied` and sets `version_unconfirmed = "
        "False`, which is what decides whether section 6 asks the vendor docs "
        "'Is {product} {version} affected by {cve}?'. A bare substring test "
        "over advisory prose cannot support that conclusion in EITHER "
        "direction: '2.4' is inside '12.4.0', '2.4.9' and the CVE year "
        "'2024', and an advisory routinely names the FIXED version too — so a "
        "target that is already PATCHED reads as confirmed-affected and the "
        "one check that would have caught it is skipped. The fix is the same "
        "shape as _auth_requirement(): parse the affected RANGE and compare "
        "versions, returning the matched phrase, rather than asking whether "
        "the characters appear. Two hits here, both at the same `if`: the "
        "satisfied.append and the flag clear.",
}


# ── tests ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def hits():
    if not os.path.exists(os.path.join(REPO, ANCHOR_FILE)):
        pytest.skip(f"{ANCHOR_FILE} not present — nothing to scan here")
    return _scan_repo()


@pytest.fixture(scope="module")
def candidates():
    if not os.path.exists(os.path.join(REPO, ANCHOR_FILE)):
        pytest.skip(f"{ANCHOR_FILE} not present — nothing to scan here")
    return _scan_repo(include_corroborated=True)


def test_detector_is_not_vacuous():
    """The detector must still flag the ORIGINAL bug, exactly as it was written.

    Without this the ratchet below can pass because the detector stopped
    detecting, which is indistinguishable from the code being clean.
    """
    # `_assess_exploit_readiness` as it stood at e1876e3e^, verbatim down to
    # the keyword tuple — including the `else:` leg that DOES probe, which must
    # not launder the `if not cookie:` leg that does not.
    src = (
        "def _assess_exploit_readiness(ip, port, analysis, session_info=None,\n"
        "                              precond_result=None, product=None):\n"
        "    a = analysis or {}\n"
        "    preconds = [str(p) for p in (a.get('preconditions') or [])]\n"
        "    pre_blob = (' '.join(preconds) + ' ' + str(a.get('summary', ''))).lower()\n"
        "    si = session_info or {}\n"
        "    blockers, satisfied = [], []\n"
        "\n"
        "    needs_auth = any(k in pre_blob for k in\n"
        "                     ('auth', 'login', 'session', 'logged', 'credential', 'cookie',\n"
        "                      'privilege', 'user ', 'account'))\n"
        "    cookie = si.get('cookie_header') if isinstance(si, dict) else None\n"
        "\n"
        "    if needs_auth:\n"
        "        if not cookie:\n"
        "            blockers.append('exploit requires authentication but NO session '\n"
        "                            'cookie was established')\n"
        "        else:\n"
        "            valid, why = _probe_session_valid(ip, port, cookie, product=product)\n"
        "            if valid:\n"
        "                satisfied.append('authenticated session is valid')\n"
        "            else:\n"
        "                blockers.append('authenticated session is NOT valid')\n"
        "    return blockers\n"
    )
    found = find_prose_gates(src, "fixture.py")
    assert found, "detector no longer flags the auth bug it was built for"
    assert found[0]["func"] == "_assess_exploit_readiness"
    assert found[0]["action"].startswith("blockers.append")
    assert "pre_blob" in found[0]["haystack"]
    assert not found[0]["corroborated"], (
        "the probing `else:` leg laundered the `if not cookie:` leg that "
        "blocks on prose alone — corroboration must be per-action")


def test_the_shipped_fix_passes():
    """`_auth_requirement()` is the model answer and must NOT be flagged.

    A guard that still fires after the fix teaches people to delete the guard.
    """
    src = (
        "def gate(ip, port, analysis, cookie):\n"
        "    a = analysis or {}\n"
        "    pre_blob = str(a.get('preconditions') or '').lower()\n"
        "    blockers = []\n"
        "    needs_auth, negated, why = _auth_requirement(pre_blob, a.get('summary'))\n"
        "    if needs_auth:\n"
        "        valid, why2 = _probe_session_valid(ip, port, cookie)\n"
        "        if not valid:\n"
        "            blockers.append('session is NOT valid — ' + why2)\n"
        "    return blockers\n"
    )
    assert find_prose_gates(src, "fixture.py") == []


def test_enum_validation_is_not_a_prose_gate():
    """`x not in <allowed set>` is validation, not a judgement about prose."""
    src = (
        "def update_exploit_status(status, description):\n"
        "    valid_statuses = ['pending', 'approved', 'rejected']\n"
        "    if status not in valid_statuses:\n"
        "        raise HTTPException(status_code=400, detail='bad status')\n"
        "    return status\n"
    )
    assert find_prose_gates(src, "fixture.py") == []


def test_substring_over_output_or_command_is_not_a_prose_gate():
    """An OUTPUT or a COMMAND is an observation — the thing we want gates to read."""
    src = (
        "def check(stdout, command, description):\n"
        "    blockers = []\n"
        "    if 'permission denied' in stdout:\n"
        "        blockers.append('the target refused')\n"
        "    if '--proxy' not in command:\n"
        "        blockers.append('command is not proxied')\n"
        "    return blockers\n"
    )
    assert find_prose_gates(src, "fixture.py") == []


def test_corroboration_must_dominate_the_action_not_merely_co_occur():
    """The trap that produced four FALSE PASSES while writing this guard.

    A `.status_code` read anywhere in the function is not corroboration. The
    observation has to constrain THIS decision — be in its test, define the
    name the test reads, or guard the blocking statement itself.
    """
    unrelated = (
        "def gate(description, client, url):\n"
        "    blockers = []\n"
        "    r = client.get(url)\n"
        "    if r.status_code == 500:\n"
        "        blockers.append('target is erroring')\n"
        "    if 'authentication' in description:\n"
        "        blockers.append('exploit requires authentication')\n"
        "    return blockers\n"
    )
    found = find_prose_gates(unrelated, "fixture.py")
    assert [h["line"] for h in found] == [6], (
        "a .status_code in a SIBLING branch corroborated a prose gate — that is "
        "the co-occurrence false pass this test exists to prevent")

    dominating = (
        "def gate(description, client, url):\n"
        "    blockers = []\n"
        "    if 'authentication' in description:\n"
        "        r = client.get(url)\n"
        "        if r.status_code in (401, 403):\n"
        "            blockers.append('exploit requires authentication')\n"
        "    return blockers\n"
    )
    assert find_prose_gates(dominating, "fixture.py") == [], (
        "a probe that DOMINATES the blocking statement is corroboration and "
        "must not be flagged")


def test_the_word_confirmed_in_prose_is_not_an_observation():
    """`confirmed_facts` as a table name in a QUERY corroborates; the word
    "confirmed" sitting in a comment, a docstring or a message does not.

    Named explicitly because it was one of the false passes: asserting on the
    string "confirmed" matched the table name AND the English word.
    """
    prose_only = (
        "def gate(description):\n"
        "    'Blocks when the advisory has not been confirmed.'\n"
        "    blockers = []\n"
        "    # confirmed_facts would be the right thing to read here\n"
        "    if 'authentication' in description:\n"
        "        blockers.append('needs auth (not confirmed)')\n"
        "    return blockers\n"
    )
    assert len(find_prose_gates(prose_only, "fixture.py")) == 1, (
        "the English word 'confirmed' was accepted as an observation")

    real_lookup = (
        "def gate(description, cur, cve):\n"
        "    blockers = []\n"
        "    cur.execute('SELECT 1 FROM confirmed_facts WHERE cve=%s', (cve,))\n"
        "    proven = cur.fetchone()\n"
        "    if 'authentication' in description and not proven:\n"
        "        blockers.append('needs auth and no fact confirms a session')\n"
        "    return blockers\n"
    )
    assert find_prose_gates(real_lookup, "fixture.py") == [], (
        "a real confirmed_facts lookup in the decision was not accepted")


def test_allow_direction_counts_too():
    """CLEARING a doubt from prose is the same defect as raising one.

    `version in advisory_text` is the live instance: an advisory names the
    FIXED version as readily as the affected one, so the substring clears
    `version_unconfirmed` for a target that is already patched — and the
    vendor-doc check that would have caught it is then skipped.
    """
    src = (
        "def gate(version, advisory_text):\n"
        "    satisfied = []\n"
        "    version_unconfirmed = bool(version)\n"
        "    adv = advisory_text or ''\n"
        "    if adv and version in adv:\n"
        "        satisfied.append('version appears in the advisory text')\n"
        "        version_unconfirmed = False\n"
        "    return satisfied, version_unconfirmed\n"
    )
    found = find_prose_gates(src, "fixture.py")
    actions = sorted(h["action"] for h in found)
    assert actions == ["satisfied.append(...)  [allow]",
                       "version_unconfirmed = False  [allow]"], actions

    # ... and a real range comparison is not a substring test at all.
    fixed = (
        "def gate(version, advisory_text):\n"
        "    satisfied = []\n"
        "    version_unconfirmed = bool(version)\n"
        "    affected, matched = _affected_range(advisory_text)\n"
        "    if affected and _version_in_range(version, affected):\n"
        "        satisfied.append('version %s is in the affected range %s' % (version, matched))\n"
        "        version_unconfirmed = False\n"
        "    return satisfied, version_unconfirmed\n"
    )
    assert find_prose_gates(fixed, "fixture.py") == []


def test_prompt_assembly_is_not_an_allow_decision():
    """`proven_lines.append(...)` builds a PROMPT; it decides nothing.

    Named because the first run of the allow-direction detector put two of
    these in the debt list, which would have been two false claims about the
    code sitting in a file people trust.
    """
    src = (
        "def _recon_strategist(recon_guidance):\n"
        "    proven_lines = []\n"
        "    if recon_guidance and 'WAF CHARACTERIZED' in recon_guidance:\n"
        "        proven_lines.append('  - class=RCE: proven-passable variants')\n"
        "    return '\\n'.join(proven_lines)\n"
    )
    assert find_prose_gates(src, "fixture.py") == []


def test_label_computation_is_not_a_gate():
    """Classifying is not blocking. Only block/allow decisions are in scope."""
    src = (
        "def classify(description):\n"
        "    if 'sql' in description:\n"
        "        return 'sqli'\n"
        "    if 'traversal' in description:\n"
        "        return 'lfi'\n"
        "    return 'unknown'\n"
    )
    assert find_prose_gates(src, "fixture.py") == []


def test_detector_reaches_live_gate_code(candidates):
    """The sweep must still REACH real gates, not just the synthetic fixtures.

    `test_no_new_prose_gates` is empty today. That is only meaningful while the
    detector is demonstrably still walking the functions where these bugs live:
    an empty result and a detector that scans nothing look identical from the
    outside, and that is precisely how four guards false-passed on 2026-10-17.

    So: prose probes that reach a gate action, in LIVE api.py. The six in
    these two functions are expected to come back CORROBORATED —

      api.py:40126/40167 _enumerate_exploit_preconditions
          `("host" in pre_blob or "script" in pre_blob ...)` AND
          `not resolved.get("hostid")`: the prose only decides whether to
          LOOK; the unmet/confirmed legs read the enumeration result.
      api.py:40235 _enumerate_exploit_preconditions
          `"sql" in pre_blob and ...` -> `_probe_injection_vectors()`.
      api.py:40935 _assess_exploit_readiness
          `idkind in pre_blob AND idkind not in resolved AND ...`: blocks only
          on an id the enumeration did not come back with.

    — while the version clause at ~41007 is NOT, and is carried as debt. If
    this ever fails, re-point it at whatever the gates are called then; do not
    delete it.
    """
    api = [c for c in candidates if c["file"] == ANCHOR_FILE]
    assert api, (
        f"the sweep found no prose-probe gate candidate in {ANCHOR_FILE}; the "
        "ratchet below is vacuous until this is re-pointed")
    reached = {c["func"] for c in api}
    expected = {"_assess_exploit_readiness", "_enumerate_exploit_preconditions"}
    assert reached & expected, (
        f"detector no longer reaches the readiness/precondition gates "
        f"(reached: {sorted(reached)})")
    for fname in sorted(reached & expected):
        corro = [c for c in api if c["func"] == fname and c["corroborated"]]
        assert corro, (
            f"{fname} has prose-probe gate candidates but NONE of them is "
            "corroborated any more — either the gate regressed to deciding on "
            "prose alone, or the corroboration detector stopped working. "
            "Both are worth a look before this assertion is relaxed.")


def test_no_new_prose_gates(hits):
    """THE RATCHET. A new prose-only gate fails here, by name."""
    new = sorted({(h["file"], h["func"]) for h in hits} - set(PROSE_GATE_DEBT))
    detail = "\n  ".join(
        f"{h['file']}:{h['line']} {h['func']}() — {h['probe']} in {h['haystack']} "
        f"-> {h['action']}"
        for h in sorted(hits, key=lambda x: (x["file"], x["line"]))
        if (h["file"], h["func"]) in set(new))
    assert not new, (
        "these gates reach a block/refuse decision from a SUBSTRING match over "
        "prose, with no observation beside it:\n  " + detail
        + "\n\nThe substring will one day match the phrase that means the "
          "OPPOSITE ('auth' is inside 'unauthenticated'). Branch on an "
          "observation — a probe result, a .status_code, a confirmed_facts "
          "lookup — or return a verdict that carries the phrase it matched, "
          "like app/rag-api/api.py::_auth_requirement. Add to "
          "PROSE_GATE_DEBT only with a reason.")


def test_debt_entries_are_not_stale(hits):
    """A fixed gate must be DELETED from the list, not left behind.

    A stale entry exempts a function that no longer needs exempting — and the
    next real violation in it would then pass silently.
    """
    live = {(h["file"], h["func"]) for h in hits}
    stale = sorted(set(PROSE_GATE_DEBT) - live)
    assert not stale, (
        "PROSE_GATE_DEBT entries no longer flagged by the detector — delete "
        "them (git history keeps the record):\n  "
        + "\n  ".join(f"{f}::{fn}" for f, fn in stale))


def test_debt_entries_carry_a_reason():
    """A debt list without reasons is a mute list; nobody can close an entry."""
    for key, why in PROSE_GATE_DEBT.items():
        assert isinstance(why, str) and len(why) > 80, (
            f"PROSE_GATE_DEBT{key} needs a real reason, not a shrug")
        assert os.path.exists(os.path.join(REPO, key[0])), (
            f"debt entry names a file that no longer exists: {key[0]}")


if __name__ == "__main__":                                 # pragma: no cover
    found = _scan_repo(include_corroborated=True)
    bad = [h for h in found if not h["corroborated"]]
    print(f"{len(found)} prose-probe gate decision(s), {len(bad)} uncorroborated")
    for h in sorted(found, key=lambda x: (x["file"], x["line"])):
        if h["corroborated"]:
            tag = f"ok   ({h['corroborated']})"
        elif (h["file"], h["func"]) in PROSE_GATE_DEBT:
            tag = "DEBT"
        else:
            tag = "NEW"
        print(f"  [{tag}] {h['file']}:{h['line']} {h['func']}() — "
              f"{h['probe']} in {h['haystack']} -> {h['action']}")
