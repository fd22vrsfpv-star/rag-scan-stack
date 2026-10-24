"""Challenge the derived fact SET, not one fact at a time.

`app/rag-api/fact_probes.py` asks the target one question per claim and now
compares each answer against a negative control. That makes an individual fact
honest. It cannot make the set coherent: every probe can be individually right
while the facts together describe a target that does not exist.

One real build's ledger, every row at confidence 0.9:

    endpoint     /s/{key}/_/download/resources/...      a TEMPLATE
    method       OPTIONS accepted on /<other>/browse    another product's route
    input_field  'command' changed the status 200->404  another vuln class

Nothing was in a position to notice, because nothing read the rows together.
This module does, and it is the "challenger" the pipeline never had: producers
(recon parsers, the spec extractor, the LLM fallback, the advisory reader) all
assert; the probes verify one assertion each; this is the only step whose job
is to disbelieve the whole picture.

DETERMINISTIC ON PURPOSE. The rules are authored as data in
`knowledge/fact_contradictions.yaml` — and embedded into `rag_documents` so the
planner can RECALL why a fact was challenged — but the decision is made here,
in Python, by exact comparison. CLAUDE.md's rule is "retrieve, then gate, never
retrieve to authorize"; a contradiction that could be argued away by a
similarity score is not a check.

What an operator extends without touching code: the DATA in the YAML (route
markers, parameter-name hints, TTLs, path-based classes). What needs code: a
new KIND of check, because a free-form expression language in YAML is code
without tests.

Pure: no database, no network, no clock of its own (ages are passed in). That
is what makes it cheap to test and impossible to get wrong by accident.

    pytest tests/test_fact_contradictions.py
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover — the loader reports it
    yaml = None

HIGH = "high"
MEDIUM = "medium"

# What the caller DOES about a contradiction. Severity alone is too blunt: one
# of these findings should UNBLOCK a build (the auth precondition was wrong),
# so "high means stop" would have the challenger stall the builds it exists to
# rescue. The rule declares its action; this module validates and reports it,
# and the CALLER applies it — keeping the decision here and the side effects
# where they can be seen.
CLEAR = "clear"            # the value is unusable; drop it, make recon re-find it
DOWNGRADE = "downgrade"    # may be right, is not evidence; re-prove before use
RELAX_AUTH = "relax_auth"  # the auth precondition is wrong; stop waiting
WARN = "warn"              # record it, change nothing
ACTIONS = (CLEAR, DOWNGRADE, RELAX_AUTH, WARN)

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_PATHS = (
    os.environ.get("KNOWLEDGE_DIR", "/knowledge") + "/fact_contradictions.yaml",
    os.path.join(_HERE, "..", "knowledge", "fact_contradictions.yaml"),
)

# ── placeholder detection ────────────────────────────────────────────────────
#
# Duplicated by design in `app/rag-api/fact_probes.py`, which is a leaf module
# with no dependencies so it can be loaded standalone by a probe runner. The
# two are pinned to a shared case table by
# tests/test_fact_contradictions.py::test_placeholder_detection_agrees — if
# they drift, a template slips past one of the two readers.
PLACEHOLDER_RE = re.compile(r"\{[^}]*\}|<[^>]+>|\.\.\.|%7B|%3C", re.I)


def has_placeholder(value) -> bool:
    """Does this value still contain an unsubstituted template placeholder?"""
    return bool(PLACEHOLDER_RE.search(str(value or "")))


class _SafeFmt(dict):
    """`"{a} {b}".format_map(_SafeFmt(a=1))` -> "1 {b}" instead of KeyError.

    A message in YAML must never be able to crash the challenger: a rule with a
    typo in its template should produce a slightly worse message, not suppress
    every contradiction after it.
    """

    def __missing__(self, key):  # pragma: no cover — exercised via format_map
        return "{%s}" % key


def _fmt(template: str, ctx: dict) -> str:
    try:
        return " ".join(str(template or "").format_map(_SafeFmt(ctx)).split())
    except Exception:  # noqa: BLE001
        return str(template or "")


def _norm(v) -> str:
    return str(v or "").strip().lower()


def _segments(path: str) -> List[str]:
    bare = str(path or "").split("?", 1)[0]
    return [s for s in bare.lower().split("/") if s]


# ── the checks ───────────────────────────────────────────────────────────────
#
# Each takes (rule, intel) and returns a list of context dicts. The caller
# turns a context into a finding, so a check never formats its own message and
# the YAML stays the single source of wording.


def _check_placeholder_in_value(rule: dict, intel: dict) -> List[dict]:
    out = []
    facts = intel.get("facts") or {}
    for field in rule.get("fields") or []:
        val = facts.get(field)
        if val and has_placeholder(val):
            out.append({"item": field, "value": str(val)[:200]})
    return out


# A product field can be FILLED and still say nothing. The CVE-Bench runner
# sends `product=unknown` whenever a challenge's .env carries no
# APPLICATION_NAME, and other callers use their own blanks. These are the
# absence of a fingerprint wearing the shape of one.
_UNFINGERPRINTED = {"unknown", "unidentified", "unidentified service",
                    "none", "null", "n/a", "na", "-", "?", "undefined",
                    "generic", "other"}


def _identities(intel: dict) -> List[str]:
    """Every name this run has for what the target IS, placeholders removed.

    `product` is what the CALLER declared; `frameworks` and
    `secondary_products` are what recon FOUND. A target can be
    `product=unknown` and `frameworks=['WordPress']` at the same time — that is
    not an unidentified target, it is an unidentified caller."""
    names = [intel.get("product")]
    for key in ("frameworks", "secondary_products"):
        v = intel.get(key)
        for item in (v if isinstance(v, (list, tuple, set)) else ([v] if v else [])):
            # secondary_products rows are dicts ({"product": ..., "version": ...});
            # detected_frameworks are plain strings. Take either.
            if isinstance(item, dict):
                names.append(item.get("product") or item.get("name"))
            else:
                names.append(item)
    out = []
    for n in names:
        n = _norm(n)
        if n and n not in _UNFINGERPRINTED and n not in out:
            out.append(n)
    return out


def _check_route_product_mismatch(rule: dict, intel: dict) -> List[dict]:
    identities = _identities(intel)
    endpoint = (intel.get("facts") or {}).get("endpoint")
    if not identities or not endpoint:
        # Nothing to contradict. An UNFINGERPRINTED target is the loud case:
        # this rule used to read the literal string "unknown" as a product
        # name, so every wp-*/jira/grafana route on a target nobody had
        # identified was "another product's route". On CVE-2023-37999
        # (2026-10-22) that downgraded the endpoint on a target the same run
        # had fingerprinted as WordPress 6.8.3 four separate times, with the
        # finding reading `carries a route marker for 'wordpress', but the
        # target was fingerprinted as 'unknown'`. You cannot prove a route
        # belongs to ANOTHER product without knowing which product this is.
        return []
    segs = _segments(endpoint)
    joined = "/".join(segs)
    out = []
    for marker, owner in (rule.get("route_markers") or {}).items():
        m = _norm(marker)
        hit = (m in segs) if "/" not in m else (m in joined)
        if not hit:
            continue
        own = _norm(owner)
        # The marker's owner IS something this target was identified as
        # (either containing the other) -> consistent, not a contradiction.
        if own and any(own in ident or ident in own for ident in identities):
            continue
        out.append({"item": "endpoint", "value": str(endpoint)[:200],
                    "owner": own, "product": identities[0], "marker": m})
    return out


def _path_is_the_field(vc: str) -> bool:
    """Ask the CLASS TABLE, not a private list.

    This rule used to carry its own `path_is_the_field_classes` in
    fact_contradictions.yaml, and that copy had drifted: it listed `lfi` (plus
    `file-read`, `file-disclosure` and `arbitrary-file-read`, which all
    canonicalise to lfi). The class table says LFI injects through a PARAMETER
    (`?page=../../etc/passwd`). The rule's action is `clear`, so on every LFI
    build a correctly-gathered parameter was DELETED as a "contradiction".

    Fail-soft to False: when the table cannot be read we decline to clear
    anything — wrongly keeping a field is recoverable, wrongly deleting the
    one real injection point is not.
    """
    try:
        try:
            from etl import vuln_classes as _VC
        except ImportError:
            import vuln_classes as _VC  # type: ignore
        return bool(_VC.path_is_the_field(_VC.canonical(vc)))
    except Exception:  # noqa: BLE001
        return False


def _check_field_kind_mismatch(rule: dict, intel: dict) -> List[dict]:
    vc = _norm(intel.get("vuln_class"))
    field = (intel.get("facts") or {}).get("input_field")
    if not vc or not field or not _path_is_the_field(vc):
        return []
    # The path-is-the-field upgrade records the ROUTE as the input field, with
    # an explanation. That is the correct state, not a contradiction.
    if "/" in str(field):
        return []
    return [{"item": "input_field", "value": str(field)[:120], "vuln_class": vc}]


def _check_field_name_class_mismatch(rule: dict, intel: dict) -> List[dict]:
    vc = _norm(intel.get("vuln_class"))
    field = _norm((intel.get("facts") or {}).get("input_field"))
    if not field or not vc:
        return []
    hints = {_norm(k): {_norm(n) for n in (v or [])}
             for k, v in (rule.get("class_field_hints") or {}).items()}
    # A name that belongs to THIS class is evidence for it, whatever else it
    # also belongs to.
    if field in hints.get(vc, set()):
        return []
    owners = sorted(c for c, names in hints.items() if field in names)
    if not owners:
        return []
    return [{"item": "input_field", "value": field, "vuln_class": vc,
             "hint_class": owners[0], "hint_classes": owners}]


def _check_auth_contradiction(rule: dict, intel: dict) -> List[dict]:
    if not intel.get("auth_required"):
        return []
    ok = {int(s) for s in (rule.get("unauthenticated_ok_statuses") or [])}
    out = []
    for obs in intel.get("auth_observations") or []:
        try:
            st = int(obs.get("status"))
        except (TypeError, ValueError):
            continue
        if st in ok:
            out.append({"item": "auth", "status": st,
                        "evidence_item": str(obs.get("item") or "the endpoint"),
                        "value": str(obs.get("value") or "")[:160]})
    return out


def _check_control_matched(rule: dict, intel: dict) -> List[dict]:
    """A probe whose negative control matched did not test anything.

    Keyed on the probe EVIDENCE rather than a status, because the status is
    `unverified` for three different reasons and only this one means "the
    instrument reads the same with nothing in it".
    """
    gathered = {str(g) for g in (intel.get("gathered_items") or [])}
    out = []
    for item, pr in (intel.get("probe_results") or {}).items():
        ev = str((pr or {}).get("evidence") or "")
        if "control matched" not in ev:
            continue
        if gathered and item not in gathered:
            continue
        out.append({"item": item, "value": str((intel.get("facts") or {}).get(item) or "")[:160],
                    "evidence": ev[:200]})
    return out


def _check_endpoint_not_observed(rule: dict, intel: dict) -> List[dict]:
    endpoint = (intel.get("facts") or {}).get("endpoint")
    if not endpoint:
        return []
    source = _norm((intel.get("fact_sources") or {}).get("endpoint"))
    weak = {_norm(s) for s in (rule.get("weak_sources")
                               or ["llm_fallback", "model_inferred", "research",
                                   "derived_vector"])}
    if source and source not in weak:
        return []
    observed = intel.get("observed_paths")
    if not observed:
        # No recon to compare against is not evidence the endpoint is invented.
        # "Unreachable is not absent" — say nothing rather than accuse.
        return []
    needle = "/" + "/".join(_segments(endpoint))
    for o in observed:
        if needle and needle in ("/" + "/".join(_segments(o))):
            return []
    return [{"item": "endpoint", "value": str(endpoint)[:200],
             "source": source or "unknown", "observed_count": len(observed)}]


def _check_stale_fact(rule: dict, intel: dict) -> List[dict]:
    ages = intel.get("fact_ages") or {}
    ttls = rule.get("ttl_seconds") or {}
    out = []
    for item, ttl in ttls.items():
        try:
            ttl_i = int(ttl)
        except (TypeError, ValueError):
            continue
        if ttl_i <= 0 or item not in ages:
            continue
        try:
            age = int(ages[item])
        except (TypeError, ValueError):
            continue
        if age > ttl_i:
            out.append({"item": item, "age_seconds": age, "ttl": ttl_i,
                        "value": str((intel.get("facts") or {}).get(item) or "")[:160]})
    return out


CHECKS = {
    "placeholder_in_value": _check_placeholder_in_value,
    "route_product_mismatch": _check_route_product_mismatch,
    "field_kind_mismatch": _check_field_kind_mismatch,
    "field_name_class_mismatch": _check_field_name_class_mismatch,
    "auth_contradiction": _check_auth_contradiction,
    "control_matched": _check_control_matched,
    "endpoint_not_observed": _check_endpoint_not_observed,
    "stale_fact": _check_stale_fact,
}


# ── loading + evaluation ─────────────────────────────────────────────────────


def load_rules(path: Optional[str] = None) -> List[dict]:
    """Rules from the YAML. Returns [] when it cannot be read — the caller
    reports that as a challenger that did not run, never as "no contradictions"."""
    if yaml is None:
        return []
    for p in ([path] if path else list(_DEFAULT_PATHS)):
        if not p or not os.path.isfile(p):
            continue
        try:
            with open(p, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return [r for r in (data.get("rules") or []) if isinstance(r, dict)]
        except Exception:  # noqa: BLE001
            continue
    return []


def evaluate(intel: dict, rules: Optional[List[dict]] = None) -> dict:
    """Challenge the fact set.

    `intel` keys, all optional:
        facts            {item: value}        the derived facts
        product          str                  fingerprinted product
        vuln_class       str
        fact_sources     {item: source}       where each value came from
        fact_ages        {item: seconds}      how old each observation is
        probe_results    {item: {status, evidence}}
        gathered_items   [item, ...]          items the gate treats as gathered
        observed_paths   [path, ...]          crawl/ZAP/OpenAPI/href paths
        auth_required    bool
        auth_observations [{item, status, value}, ...]

    Returns {findings, actions, high, medium, unimplemented,
    rules_evaluated, ran}. `actions` maps each action name to the items it
    applies to, so a caller applies them without re-deriving the mapping.
    `ran` is False when no rules could be loaded — the three-outcome rule
    applies to the challenger itself: "no contradictions found" and "the
    challenger did not run" must never look the same.
    """
    rules = load_rules() if rules is None else rules
    out = {"findings": [], "high": 0, "medium": 0, "unimplemented": [],
           "rules_evaluated": 0, "ran": bool(rules)}
    for rule in rules or []:
        check = CHECKS.get(str(rule.get("check") or ""))
        if check is None:
            # Reported, never silent: a rule naming a check nobody implemented
            # is a rule the operator believes is protecting them.
            out["unimplemented"].append(
                {"id": rule.get("id"), "check": rule.get("check")})
            continue
        out["rules_evaluated"] += 1
        try:
            hits = check(rule, intel or {})
        except Exception as e:  # noqa: BLE001
            out["unimplemented"].append(
                {"id": rule.get("id"), "check": rule.get("check"),
                 "error": type(e).__name__})
            continue
        sev = _norm(rule.get("severity")) or MEDIUM
        act = _norm(rule.get("action")) or WARN
        if act not in ACTIONS:
            # An unknown action is reported and treated as WARN. Guessing at
            # what an operator meant by a typo'd action is how a `warn` becomes
            # a `clear` that silently deletes a correct fact.
            out["unimplemented"].append(
                {"id": rule.get("id"), "action": act, "reason": "unknown action"})
            act = WARN
        for ctx in hits or []:
            out["findings"].append({
                "rule_id": rule.get("id"),
                "severity": sev,
                "action": act,
                "item": ctx.get("item"),
                "value": ctx.get("value"),
                "message": _fmt(rule.get("message"), ctx),
                "why": _fmt(rule.get("why"), ctx),
                "remedy": _fmt(rule.get("remedy"), ctx),
                "context": ctx,
            })
            if sev == HIGH:
                out["high"] += 1
            else:
                out["medium"] += 1
    # Deterministic order so two runs of the same facts render identically.
    out["findings"].sort(key=lambda f: (0 if f["severity"] == HIGH else 1,
                                        str(f["rule_id"]), str(f["item"])))
    out["actions"] = {a: [f["item"] for f in out["findings"] if f["action"] == a]
                      for a in ACTIONS}
    return out


def summarize(result: dict) -> str:
    """One line per finding, for a trace or a prompt block."""
    if not (result or {}).get("ran"):
        return "fact challenge DID NOT RUN (no rules loaded) — absence of findings proves nothing"
    f = result.get("findings") or []
    if not f:
        return "fact challenge: %d rules, no contradictions" % result.get("rules_evaluated", 0)
    lines = ["fact challenge: %d contradiction(s) across %d rules"
             % (len(f), result.get("rules_evaluated", 0))]
    for x in f:
        lines.append("  [%s/%s] %s: %s" % (x["severity"].upper(), x.get("action", WARN),
                                           x["rule_id"], x["message"]))
    return "\n".join(lines)
