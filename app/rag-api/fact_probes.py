"""Test cases that PROVE a gathered fact, before synthesis is allowed to use it.

The gather manifest already records a fact and where it came from:

    [gathered] endpoint    = /business-directory  (via candidate_probe:HEAD 301)
    [gathered] method      = GET,POST             (via probe)
    [gathered] input_field = listingfields        (via llm_fallback)

Two things were wrong with that. The manifest is PROSE — rendered into the
prompt and never checked by anything — and `llm_fallback` means the model
guessed. On CVE-2024-4443 the guess was RIGHT: `listingfields` is the
vulnerable parameter named in the advisory. It appeared 22 times in that run's
trace and in **0 of the 26 dispatched commands**, every one of which attacked
`?dosrch=1&q=&wpbdp_view=search` instead. A fact that is gathered and then
ignored is worth exactly as much as one that was never gathered.

So each probeable fact gets a test case here. A probe returns one of THREE
outcomes, never two:

    confirmed  — observed. Evidence is the observation, quoted.
    refuted    — observed to be false. The loop must not retry it.
    unverified — the probe could not run (no network, timeout, missing input).
                 NOT a refutation. "Unreachable is not absent" is this repo's
                 most expensive recurring bug; a probe that could not run must
                 never be recorded as a disproof.

Probes are deliberately CHEAP and READ-ONLY: a HEAD or a single GET. They run
before synthesis, so their cost is paid once per build rather than once per
refine iteration, and they must not themselves be the thing that breaks a
target.

The `http` argument is injected so this module has no network dependency of its
own and can be tested with a stub. It is called as
`http(method, url, **kwargs) -> object with .status_code and .text`.
"""
from __future__ import annotations

from typing import Callable, Optional

CONFIRMED = "confirmed"
REFUTED = "refuted"
UNVERIFIED = "unverified"


class ProbeResult:
    """(status, evidence, method, probe_id) — with the reason always attached."""

    __slots__ = ("status", "evidence", "method", "probe_id", "value")

    def __init__(self, status, evidence, method, probe_id, value=None):
        self.status = status
        self.evidence = str(evidence or "")[:500]
        self.method = method
        self.probe_id = probe_id
        self.value = value

    def __repr__(self):  # pragma: no cover — debugging aid
        return "ProbeResult(%s, %r, probe=%s)" % (self.status, self.evidence[:60], self.probe_id)

    @property
    def proven(self) -> bool:
        return self.status == CONFIRMED


def _unverified(probe_id, why) -> ProbeResult:
    """The probe could not RUN — missing input, timeout, exception.

    Never a refutation: a check we failed to perform says nothing about the
    target.
    """
    return ProbeResult(UNVERIFIED, "probe did not run: %s" % why, "probe", probe_id)


def _inconclusive(probe_id, why) -> ProbeResult:
    """The probe RAN and could not decide.

    Distinct from `_unverified` on purpose. Both are UNVERIFIED to a caller —
    neither is permission to proceed — but "I could not look" and "I looked and
    could not tell" send an operator to different fixes, and collapsing them is
    how this repo keeps rediscovering that unreachable is not absent.
    """
    return ProbeResult(UNVERIFIED, "probe ran, inconclusive: %s" % why,
                       "probe", probe_id)


def probe_target_reachable(http: Callable, base: str) -> ProbeResult:
    """Does the target answer HTTP at all?

    ANY status code confirms reachability — a 404 proves there is a server
    there just as well as a 200 does. Only a transport failure refutes it.
    """
    pid = "target_reachable"
    try:
        r = http("GET", base, timeout=8)
    except Exception as e:  # noqa: BLE001
        # A connection error IS evidence the target is not reachable from here,
        # which is a real refutation — unlike a probe we never attempted.
        return ProbeResult(REFUTED, "no HTTP response: %s" % type(e).__name__,
                           "probe", pid)
    return ProbeResult(CONFIRMED, "HTTP %s from %s" % (r.status_code, base),
                       "probe", pid, value=str(r.status_code))


def probe_endpoint_exists(http: Callable, base: str, path: str) -> ProbeResult:
    """Is the claimed endpoint actually served?

    404/410 refutes. Anything else — including 401/403, which prove the path
    exists and is protected — confirms. A 403 on the right path is a far better
    starting point than a 200 on the wrong one.
    """
    pid = "endpoint_exists"
    if not path:
        return _unverified(pid, "no endpoint claimed")
    url = base.rstrip("/") + "/" + str(path).lstrip("/")
    try:
        r = http("GET", url, timeout=8)
    except Exception as e:  # noqa: BLE001
        return _unverified(pid, "%s requesting %s" % (type(e).__name__, url))
    if r.status_code in (404, 410):
        return ProbeResult(REFUTED, "HTTP %s at %s — path not served"
                           % (r.status_code, url), "probe", pid)
    return ProbeResult(CONFIRMED, "HTTP %s at %s" % (r.status_code, url),
                       "probe", pid, value=path)


def probe_input_field(http: Callable, base: str, path: str, field: str,
                      marker: Optional[str] = None) -> ProbeResult:
    """Does the endpoint ACCEPT the claimed parameter?

    This is the fact that matters most and the one that was purely a guess.
    The test is deliberately weak on purpose: we are proving the parameter is
    *accepted*, not that it is injectable. Proving injectability is the
    exploit's job; proving the parameter exists is a precondition for even
    trying, and getting it wrong wastes the whole build.

    Confirmed when the parameter is reflected, or when supplying it changes the
    response from the same request without it. Unverified — never refuted —
    when neither happens: plenty of real injection points are blind, and
    refuting `listingfields` because it does not echo would be worse than
    saying nothing.
    """
    pid = "input_field"
    if not field:
        return _unverified(pid, "no input field claimed")
    url = base.rstrip("/") + "/" + str(path or "").lstrip("/")
    token = marker or "pf0prb"
    sep = "&" if "?" in url else "?"
    try:
        with_param = http("GET", "%s%s%s=%s" % (url, sep, field, token), timeout=8)
        without = http("GET", url, timeout=8)
    except Exception as e:  # noqa: BLE001
        return _unverified(pid, "%s probing %s" % (type(e).__name__, field))
    body = getattr(with_param, "text", "") or ""
    if token in body:
        return ProbeResult(CONFIRMED,
                           "parameter %r reflected in the response (HTTP %s)"
                           % (field, with_param.status_code),
                           "probe", pid, value=field)
    base_body = getattr(without, "text", "") or ""
    if with_param.status_code != without.status_code:
        return ProbeResult(CONFIRMED,
                           "parameter %r changed the status (%s -> %s)"
                           % (field, without.status_code, with_param.status_code),
                           "probe", pid, value=field)
    if base_body and body and len(body) != len(base_body):
        return ProbeResult(CONFIRMED,
                           "parameter %r changed the response size (%d -> %d bytes)"
                           % (field, len(base_body), len(body)),
                           "probe", pid, value=field)
    return _inconclusive(
        pid, "parameter %r neither reflected nor changed the response — this is "
             "NOT a refutation, a blind injection point looks exactly like this"
             % field)


def probe_method_allowed(http: Callable, base: str, path: str, method: str) -> ProbeResult:
    """Is the HTTP verb accepted on that path? 405 refutes."""
    pid = "method_allowed"
    if not method:
        return _unverified(pid, "no method claimed")
    verb = str(method).split(",")[0].strip().upper()
    url = base.rstrip("/") + "/" + str(path or "").lstrip("/")
    try:
        r = http(verb, url, timeout=8)
    except Exception as e:  # noqa: BLE001
        return _unverified(pid, "%s sending %s" % (type(e).__name__, verb))
    if r.status_code == 405:
        return ProbeResult(REFUTED, "HTTP 405 — %s not allowed on %s" % (verb, url),
                           "probe", pid)
    return ProbeResult(CONFIRMED, "%s accepted on %s (HTTP %s)"
                       % (verb, url, r.status_code), "probe", pid, value=verb)


# claim_type -> (callable, required manifest keys). The runner skips a probe
# whose inputs are absent and records UNVERIFIED with that reason, so a missing
# input is visible rather than silently treated as a pass.
PROBES = {
    "target_reachable": (probe_target_reachable, ()),
    "endpoint_exists": (probe_endpoint_exists, ("endpoint",)),
    "input_field": (probe_input_field, ("endpoint", "input_field")),
    "method_allowed": (probe_method_allowed, ("endpoint", "method")),
}


def run_probes(http: Callable, base: str, facts: dict, marker: str = None) -> dict:
    """{claim_type: ProbeResult} for every probe whose inputs are present.

    `facts` is the gather manifest's flat key->value map. Never raises: a probe
    that blows up is recorded as UNVERIFIED with the exception name, because an
    exception in our prober says nothing about the target.
    """
    out = {}
    facts = facts or {}
    for claim, (fn, needs) in PROBES.items():
        missing = [k for k in needs if not facts.get(k)]
        if missing:
            out[claim] = _unverified(claim, "missing input(s): %s" % ", ".join(missing))
            continue
        try:
            if claim == "target_reachable":
                out[claim] = fn(http, base)
            elif claim == "endpoint_exists":
                out[claim] = fn(http, base, facts["endpoint"])
            elif claim == "input_field":
                out[claim] = fn(http, base, facts["endpoint"], facts["input_field"], marker)
            elif claim == "method_allowed":
                out[claim] = fn(http, base, facts["endpoint"], facts["method"])
        except Exception as e:  # noqa: BLE001
            out[claim] = _unverified(claim, "prober raised %s" % type(e).__name__)
    return out


# ── enforcement ───────────────────────────────────────────────────────────────
#
# Proving a fact is only half of it. On CVE-2024-4443 the vulnerable parameter
# `listingfields` was gathered, recorded, rendered into the prompt — and used
# in NONE of the 26 dispatched commands. Scoring that fact higher would not
# have changed one of them. Something has to CHECK the command.
#
# This is the same shape as the axis gate and the scope gate: the model
# proposes, a deterministic non-LLM check disposes. It differs from the scope
# gate in one important way — scope is a SAFETY boundary and fails closed,
# whereas this is a QUALITY check and fails OPEN. If we cannot tell whether the
# command uses the fact, the command still goes; refusing on an unreadable
# check would stall builds for a reason nobody could see.

def _encodings(value: str) -> set:
    """The spellings a parameter name legitimately takes in a command."""
    v = str(value or "")
    out = {v, v.lower()}
    try:
        from urllib.parse import quote
        out.add(quote(v))
        out.add(quote(v, safe=""))
    except Exception:  # noqa: BLE001
        pass
    # bracketed array params are freely rewritten between x[1] and x%5B1%5D
    out.add(v.replace("[", "%5B").replace("]", "%5D"))
    return {x for x in out if x}


def command_uses_fact(command: str, value: str) -> bool:
    """True when `command` references `value` in any reasonable spelling.

    Case-insensitive, percent-encoding aware. A substring test is the right
    tool here: the value is a parameter or path that must literally appear in
    the request for the request to exercise it.
    """
    if not command or not value:
        return True          # nothing to check -> nothing to refuse
    hay = str(command).lower()
    return any(e.lower() in hay for e in _encodings(value))


def enforce_facts(command: str, required: dict) -> Optional[str]:
    """Refusal string when `command` ignores a PROVEN fact, else None.

    `required` is {label: value} — only facts the caller has already decided
    are strong enough to insist on (harness-declared, or probe-confirmed).
    Deciding WHICH facts are strong enough is the caller's job, so this stays a
    pure string check with no notion of confidence.

    Returns None when there is nothing to enforce, which is the common case and
    the safe one.
    """
    if not command:
        return None
    missing = [(k, v) for k, v in (required or {}).items()
               if v and not command_uses_fact(command, v)]
    if not missing:
        return None
    bits = ", ".join("%s=%r" % (k, v) for k, v in missing)
    return (
        "the command does not use proven fact(s): %s. These were established by "
        "probe or declared by the harness itself, so a command that does not "
        "reference them is not exercising the vulnerability we identified — on "
        "CVE-2024-4443 the parameter `listingfields` was proven and then absent "
        "from all 26 dispatched commands, every one of which failed. Rebuild "
        "the command around the proven fact(s)." % bits)


# Values that cannot discriminate. `endpoint_exists = '/'` was armed on a real
# run (CVE-2024-22120, 2026-10-15): every URL contains "/", so enforcing it can
# never refuse anything. It is not harmful, but it pads the armed set and makes
# the gate look like it is checking more than it is — and a guard that cannot
# fail is the thing CLAUDE.md warns is worse than no guard, because it is
# mistaken for coverage.
_UNIVERSAL_TOKENS = {"/", "//", ".", "..", "-", "_", "?", "&", "=",
                     "http", "https", "www", "com", "html", "php", "/ ", "''",
                     "curl", "get", "post", "index", "index.php", "index.html",
                     # Front controllers and default documents: on the stacks
                     # we actually test (WordPress, PHP apps, Tomcat) every
                     # request reaches one of these, so insisting on it refuses
                     # nothing. Stored normalised — `is_enforceable_value`
                     # strips slashes before comparing.
                     "index.htm", "default.aspx", "index.jsp", "index.asp",
                     "wp-admin", "admin.php", "home", "main.php", "app.php"}
_MIN_DISCRIMINATING_LEN = 3


def is_enforceable_value(value) -> bool:
    """True when insisting on `value` could actually refuse a command.

    A value is enforceable when it is long enough to be distinctive and is not
    a token every HTTP command carries anyway. Everything else is dropped from
    the armed set rather than silently passing every check.

    The stoplist is matched against the value NORMALISED, not raw. The first
    version compared raw, so `index.php` was caught and `/index.php` was not —
    and CVE-2024-36412 duly armed `{'endpoint_exists': '/index.php'}` on a
    WordPress target where every single request hits that path. That is the
    same "guard that cannot fail" this function exists to prevent, reintroduced
    by the fix for it. Leading/trailing slashes and a leading dot carry no
    discriminating power, so they are stripped before the comparison.
    """
    v = str(value or "").strip()
    if len(v) < _MIN_DISCRIMINATING_LEN:
        return False
    norm = v.lower().strip("/").lstrip(".")
    if v.lower() in _UNIVERSAL_TOKENS or norm in _UNIVERSAL_TOKENS:
        return False
    # Normalising can empty the value ("/", "///", "..") — nothing left to match.
    if len(norm) < _MIN_DISCRIMINATING_LEN:
        return False
    # A path whose only content is separators ("/", "/ /", "//") discriminates
    # nothing even though it clears the length bar.
    if not any(ch.isalnum() for ch in v):
        return False
    return True
