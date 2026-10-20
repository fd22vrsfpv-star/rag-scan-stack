"""A PoC request as DATA, not as a shell string.

Why this exists
---------------
Synth asks the model for a shell command, as one string, inside a JSON field.
That single decision is upstream of most of the ways a build fails before it
ever reaches the target. Measured on the trace archive (5,269 dispatched
rows, 2026-09-28 → 2026-10-20):

    444  shell_syntax        the model lost the quoting -- a shell string
                             inside a JSON field is escaped twice
    296  prerun_probe_fail   the probe had to RE-PARSE that string to find
                             the target URL, and for an SSRF/OOB command it
                             picked the payload's callback sink instead
     83  prerun_tool_missing `SELECT` and `auth` reached the shell as command
                             head tokens -- a SQL fragment routed as a program

None of those are the model failing to find a vulnerability. They are the
model, and then the platform, failing to agree on a string.

A chained one-liner also fails as a UNIT:

    CANARY=POCz1; curl ... ; sleep 2 ; curl .../done | grep -q "$CANARY"

succeeds or fails as a whole, so "iteration 3 FAILED" cannot say which step
failed. That is what "4 iterations, all FAILED" was hiding.

So: the model describes WHAT to send, this module decides how to spell it.

Design
------
* **Quoting stops being the model's problem.** `to_curl` renders every value
  through `shlex.quote`. A body containing `' OR 1=1--` or a nested JSON
  document needs no escaping decisions from anyone.

* **No shell variables.** A canary is written `{{CANARY}}` and substituted
  here. The archive's `$CANARY` probe failures were all commands that DID set
  the variable -- the shell would have expanded it, but the probe read the
  text without a shell and saw a literal. Remove the variable, remove the
  class.

* **Steps are separate items.** Each carries its own `expect`, so a 3-step
  exploit reports which step failed instead of one opaque verdict. They are
  still rendered into one script for the listener, because the listener's
  contract is a command -- but the structure survives into the trace.

* **One shape, both lanes.** The dict here is the shape `_curl_to_request`
  already produces, so the Python lane consumes it directly and the shell
  lane gets `to_curl`. The probe reads `url` rather than guessing it.

This module is pure: no I/O, no DB, no network. `etl/` is bind-mounted into
rag-api, kali-listener and exploit-runner, so all three render identically --
the same reason `attack_proxy` and `proof_anchor` live here.
"""

from __future__ import annotations

import json
import shlex
from typing import Any, Dict, List, Optional, Tuple

#: The placeholder a plan uses for this run's canary. Deliberately NOT a shell
#: variable: `$CANARY` only has a value inside a shell, and everything that
#: reads a command without running one (the probe, the fact gate, the axis
#: comparison, a human) sees the literal text instead.
CANARY_TOKEN = "{{CANARY}}"

#: Marks a captured value inside a string that is about to be shell-quoted.
#: `\x00` cannot appear in a shell command or an HTTP body, so it cannot
#: collide with payload text — which `"$name"` could.
CAPTURE_SENTINEL = "\x00CAP:%s\x00"

#: What a step may contain. Kept small on purpose — every field here is one
#: the model must choose correctly, and the 444 syntax failures came from
#: giving it a field with infinite freedom.
REQUEST_FIELDS = (
    "method", "url", "headers", "body", "json", "query", "cookies",
    "auth", "verify", "timeout", "follow_redirects",
)

_DEFAULTS: Dict[str, Any] = {
    "method": "GET",
    "url": "",
    "headers": {},
    "body": None,
    "query": {},
    "cookies": {},
    "auth": None,
    "verify": True,
    "timeout": 30,
    "follow_redirects": False,
}


class RequestSpecError(ValueError):
    """The plan is not renderable. Carries a message aimed at the MODEL."""


# ── normalisation ───────────────────────────────────────────────────────────

def normalise(req: Dict[str, Any]) -> Dict[str, Any]:
    """Fill defaults, coerce types, and reject what cannot be rendered.

    Raises `RequestSpecError` with a message written for the model to act on,
    because this runs in the refine loop and the message becomes the feedback.
    """
    if not isinstance(req, dict):
        raise RequestSpecError("a request must be an object with at least a `url`")

    out = dict(_DEFAULTS)
    out["headers"] = {}
    out["query"] = {}
    out["cookies"] = {}
    for k, v in req.items():
        if k in REQUEST_FIELDS:
            out[k] = v

    url = str(out.get("url") or "").strip()
    if not url:
        raise RequestSpecError("`url` is required and must be absolute, e.g. "
                               "http://10.0.0.5:8080/api/login")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise RequestSpecError(
            "`url` must include the scheme and host — %r is relative. The "
            "exploit has to say which host it attacks." % (url[:60],))
    out["url"] = url

    out["method"] = str(out.get("method") or "GET").upper()

    for field in ("headers", "query", "cookies"):
        v = out.get(field) or {}
        if not isinstance(v, dict):
            raise RequestSpecError("`%s` must be an object of name -> value, not %s"
                                   % (field, type(v).__name__))
        out[field] = {str(k): "" if x is None else str(x) for k, x in v.items()}

    # `json` is sugar for a JSON body: the model writes an object and never
    # has to escape quotes inside a quoted shell argument.
    if req.get("json") is not None:
        if out.get("body"):
            raise RequestSpecError("give either `body` (a raw string) or `json` "
                                   "(an object), not both")
        out["body"] = json.dumps(req["json"], separators=(",", ":"))
        out["headers"].setdefault("Content-Type", "application/json")
    out.pop("json", None)

    if out.get("body") is not None and not isinstance(out["body"], str):
        out["body"] = json.dumps(out["body"], separators=(",", ":"))

    if isinstance(out.get("auth"), (list, tuple)) and len(out["auth"]) == 2:
        out["auth"] = (str(out["auth"][0]), str(out["auth"][1]))
    elif out.get("auth") is not None and not isinstance(out["auth"], tuple):
        out["auth"] = None

    try:
        out["timeout"] = max(1, min(600, int(out.get("timeout") or 30)))
    except Exception:  # noqa: BLE001
        out["timeout"] = 30
    out["verify"] = bool(out.get("verify", True))
    out["follow_redirects"] = bool(out.get("follow_redirects", False))
    return out


def interpolate_captures(obj: Any) -> Any:
    """Turn `{{name}}` references into shell `"$name"` for captured values.

    The model writes `{{csrf}}` in a later step's body; the renderer turns it
    into the shell variable the extraction above assigned. The model still
    never writes a shell variable or decides any quoting — `to_curl` quotes
    the whole value, and a `$name` inside a double-quoted argument expands.
    """
    import re as _re
    if isinstance(obj, str):
        # A SENTINEL, not shell text. Emitting `"$name"` here would be swallowed
        # by shlex.quote — it wraps the whole value in single quotes, where a
        # variable does not expand — and a payload containing the literal text
        # `"$foo"` would become an expansion. The sentinel is converted after
        # quoting, so only real capture references escape the quotes.
        return _re.sub(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}",
                       lambda m: CAPTURE_SENTINEL % m.group(1), obj)
    if isinstance(obj, list):
        return [interpolate_captures(x) for x in obj]
    if isinstance(obj, dict):
        return {k: interpolate_captures(v) for k, v in obj.items()}
    return obj


def substitute(obj: Any, canary: Optional[str]) -> Any:
    """Replace `{{CANARY}}` throughout a plan. Recursive over dict/list/str.

    Done HERE rather than by the shell, so the rendered command carries the
    real value and every reader -- probe, fact gate, axis comparison, operator
    -- sees what will actually be sent.
    """
    if canary is None:
        return obj
    if isinstance(obj, str):
        return obj.replace(CANARY_TOKEN, canary)
    if isinstance(obj, list):
        return [substitute(x, canary) for x in obj]
    if isinstance(obj, dict):
        return {k: substitute(v, canary) for k, v in obj.items()}
    return obj


# ── rendering ───────────────────────────────────────────────────────────────

def _q(value: str) -> str:
    """shlex.quote, then let capture references out of the quotes.

    shlex.quote wraps a value in single quotes, where `$name` is literal. A
    capture has to step outside them: `'a='"$csrf"'&b=1'`. Done after quoting
    and only for the sentinel, so a payload containing the characters `$csrf`
    stays data.
    """
    import re as _re
    out = shlex.quote(value)
    return _re.sub(r"\x00CAP:([A-Za-z_][A-Za-z0-9_]*)\x00",
                   lambda m: "'\"$%s\"'" % m.group(1), out)


def to_curl(req: Dict[str, Any], *, silent: bool = True,
            include_headers: bool = True) -> str:
    """One normalised request -> one curl command, correctly quoted.

    Every value goes through `shlex.quote`, so a body of `' OR 1=1--` or a
    nested JSON document is rendered without anyone making an escaping
    decision. That is the whole point: 444 of the archive's refusals were a
    quoting decision made wrongly.
    """
    r = normalise(req)
    parts: List[str] = ["curl"]
    if silent:
        parts += ["-s", "-S"]
    if include_headers:
        parts.append("-i")
    if not r["verify"]:
        parts.append("-k")
    if r["follow_redirects"]:
        parts.append("-L")
    parts += ["--max-time", str(r["timeout"])]
    if r["method"] != "GET" or r["body"] is not None:
        parts += ["-X", r["method"]]
    for k, v in r["headers"].items():
        parts += ["-H", _q(f"{k}: {v}")]
    if r["cookies"]:
        jar = "; ".join(f"{k}={v}" for k, v in r["cookies"].items())
        parts += ["-b", _q(jar)]
    if r["auth"]:
        parts += ["-u", shlex.quote(f"{r['auth'][0]}:{r['auth'][1]}")]
    if r["body"] is not None:
        # --data-raw, never -d: -d strips newlines and @ means "read a file",
        # so a body starting with @ would silently become a file read.
        parts += ["--data-raw", _q(r["body"])]
    url = r["url"]
    if r["query"]:
        from urllib.parse import urlencode
        sep = "&" if "?" in url else "?"
        url = url + sep + urlencode(r["query"])
    parts.append(_q(url))
    return " ".join(parts)


def _extract_lines(step: Dict[str, Any], var: str) -> List[str]:
    """Shell that pulls named values out of a step's response.

    The one thing shell-chaining genuinely gave the model: a CSRF token or
    session id fetched in one request and used in the next. A plan with no way
    to express that would force `csrf_token=REPLACE_WITH_CSRF` into the body —
    observed on the very first live plan this prompt produced.

    So the model supplies the PATTERN and we generate the plumbing. That keeps
    the property that matters: the model never writes shell quoting. The
    archive's nastiest commands were exactly this idiom (a grep -oP with a
    nested-quoted character class) and 15 of them were refused for unbalanced
    quotes. The pattern is a PCRE using ``\\K``, so the match IS the value and
    there are no capture groups to address.
    """
    out: List[str] = []
    for name, spec in (step.get("extract") or {}).items():
        if not str(name).isidentifier():
            raise RequestSpecError(
                "extract name %r must be a plain identifier — it becomes a "
                "{{%s}} token later steps reference" % (name, name))
        pat = spec.get("grep_p") if isinstance(spec, dict) else spec
        if not pat:
            raise RequestSpecError(
                "extract %r needs `grep_p`: a PCRE whose \\K marks where the "
                "value starts, e.g. name=\"csrf\"\\s+value=\"\\K[^\"]+" % (name,))
        out.append("%s=$(printf '%%s' \"$%s\" | grep -oP %s | head -1)"
                   % (name, var, shlex.quote(str(pat))))
        # An empty capture is a silent wrong answer: the next request goes out
        # with the parameter blank and the failure looks like the exploit, not
        # the extraction.
        out.append("[ -n \"$%s\" ] || echo 'EXTRACT-FAILED: %s'" % (name, name))
    return out


def to_script(steps: List[Dict[str, Any]], *, canary: Optional[str] = None) -> str:
    """A multi-step plan -> one script the listener can run.

    The listener's contract is a command, so the steps are joined — but each
    is rendered independently and announced with a marker, so the OUTPUT says
    which step produced what. A chained one-liner cannot do that, which is why
    "iteration 3 FAILED" never said which part failed.
    """
    # Canary first (a literal value), then capture references (which become
    # shell variables) — order matters only in that both must happen before
    # rendering, and a canary is never a capture name.
    plan = interpolate_captures(substitute(steps, canary))
    lines: List[str] = []
    for n, step in enumerate(plan, 1):
        sid = str(step.get("id") or f"step{n}")
        wait = step.get("wait_seconds")
        if wait:
            lines.append(f"sleep {int(wait)}")
        lines.append("echo " + shlex.quote(f"--- STEP {sid} ---"))
        cmd = to_curl(step.get("request") or step)
        if step.get("extract"):
            # Capture the response so values can be pulled out of it, and
            # still print it — the verdict reads the combined output.
            var = "_r%d" % n
            lines.append("%s=$(%s)" % (var, cmd))
            lines.append("printf '%%s\\n' \"$%s\"" % var)
            lines.extend(_extract_lines(step, var))
        else:
            lines.append(cmd)
    return "\n".join(lines)


def validate_plan(steps: Any) -> List[Dict[str, Any]]:
    """Check a whole plan, raising a model-facing message on the first fault."""
    if isinstance(steps, dict):
        steps = [steps]
    if not isinstance(steps, list) or not steps:
        raise RequestSpecError("a plan is a non-empty list of steps, each with a `request`")
    out = []
    for n, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise RequestSpecError(f"step {n} is not an object")
        req = step.get("request") or {k: v for k, v in step.items() if k in REQUEST_FIELDS}
        try:
            normalise(req)
        except RequestSpecError as e:
            raise RequestSpecError(f"step {n} ({step.get('id') or n}): {e}") from None
        out.append(step)
    return out


def target_of(steps: Any) -> Tuple[Optional[str], Optional[str]]:
    """(method, url) of the step that attacks the target — the FIRST step.

    This is the question `_prerun_payload_probe` had to answer by re-parsing a
    shell string, which is how it came to probe the exploit's own callback
    sink. With a plan there is nothing to guess.
    """
    try:
        plan = validate_plan(steps)
    except RequestSpecError:
        return None, None
    first = plan[0]
    req = normalise(first.get("request") or first)
    return req["method"], req["url"]
