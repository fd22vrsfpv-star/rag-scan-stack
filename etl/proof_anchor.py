"""Is the proof tied to THIS exploit's effect? Per proof kind, not per canary.

`verified = success and anchored`, and `anchored` meant one thing: the
injected canary appears in the assertion. That is exactly right for a
reflection proof and structurally impossible for several others:

    echo / canary regex                     anchored=True
    oob sink marker (SINK-VERIFIED:<can>)   anchored=True
    file read, content signature            anchored=False   <-- root:x:0:0:
    timing only ({"min_seconds": 5})        anchored=False

So a PERFECT file read could never be verified. The craft guidance correctly
tells a file-read class to assert on content only the real file has, and that
a returning canary is a REFUTATION — which makes the canary rule unsatisfiable
for the class by design. Same for blind timing: a scaled-payload-confirmed
SLEEP has no canary to anchor to.

OOB survived only by accident of string formatting: the sink tail happens to
emit `SINK-VERIFIED: <canary>`, so the canary lands in the regex. Remove the
canary from that marker and every callback proof stops being verifiable too.

The question anchoring actually asks is "could this have passed WITHOUT the
exploit?". What answers it differs by proof kind:

    echo           the canary we injected came back
    file_content   the response carries a signature only the real file has,
                   AND the command asked for that file
    oob            the sink marker carries THIS run's canary
    timing         the scaled-payload re-run confirmed the delay scales
    status_change  a two-request comparison differed
    side_effect    a follow-up read observed the change

STRICTER OR EQUAL, NEVER LOOSER BY ACCIDENT. Every branch below demands
positive evidence tied to the run; an unknown class falls back to the canary
rule, so nothing becomes verifiable that was not before unless its proof kind
says what ties it.

Pure: no network, no database. The caller supplies the command, the assertion
and the verdict method it already has.

    pytest tests/test_proof_anchor.py
"""
from __future__ import annotations

import re
from typing import Optional

# Verdict methods that mean the TIMING claim was confirmed by re-running with a
# scaled payload (CLAUDE.md's blind-timing rule). An unconfirmed or
# unconfirmable latency is explicitly NOT an anchor.
_TIMING_CONFIRMED = ("latency_confirmed", "latency_confirmed_anchored")

# Markers the sink-verification tail emits. The canary must appear alongside
# one of these, or the "callback" could be any prior run's.
_OOB_MARKERS = ("SINK-VERIFIED", "LISTENER-HIT")


def _regex_of(assertion) -> str:
    return str((assertion or {}).get("expect_regex") or "")


def _declared(assertion, canary) -> bool:
    """An assertion that declares itself anchored, with THIS run's canary.

    `_reanchor()` builds this shape. It existed with zero call sites, which is
    part of why non-echo proofs had no route to being anchored.
    """
    a = assertion or {}
    return bool(canary and a.get("cve_anchored") and a.get("canary") == canary)


def anchored_echo(assertion, canary) -> bool:
    """The original rule: the assertion requires the canary we injected."""
    if not canary:
        return False
    return _declared(assertion, canary) or canary in _regex_of(assertion)


def anchored_oob(assertion, canary) -> bool:
    """A sink marker carrying THIS run's canary.

    The canary is what makes it this run's callback rather than a stale one
    from a previous attempt against the same sink.
    """
    if not canary:
        return False
    rx = _regex_of(assertion)
    if not any(m in rx for m in _OOB_MARKERS):
        return _declared(assertion, canary)
    return canary in rx or _declared(assertion, canary)


def anchored_timing(assertion, verdict_method) -> bool:
    """Confirmed by the scaled-payload re-run, never by a single elapsed.

    A target that takes 5s on every request looks identical to a verified
    SLEEP(5) when only one elapsed is observed, which is why `min_seconds`
    alone can never anchor.
    """
    if not (assertion or {}).get("min_seconds"):
        return False
    return str(verdict_method or "") in _TIMING_CONFIRMED


def anchored_file_content(assertion, command, signatures) -> bool:
    """The response carries a signature only the real file has, AND the
    command asked for that file.

    Both halves are required. The signature alone could match a page that
    happens to contain the pattern; the request alone proves nothing was
    returned. Together they say: we asked for this file and got its content.

    `signatures` is {requested-thing: regex} from
    knowledge/payload_variants.yaml — the same table the craft guidance offers.
    """
    rx = _regex_of(assertion)
    if not rx or not signatures:
        return False
    cmd = str(command or "")
    for target, sig in signatures.items():
        if not sig or sig not in rx:
            continue
        # The command must reference the file this signature belongs to.
        # Compare on the last path segment so `/etc/passwd`, `..%2fetc%2fpasswd`
        # and `....//etc/passwd` all count as asking for passwd.
        leaf = str(target).replace("\\", "/").rstrip("/").split("/")[-1]
        if not leaf:
            continue
        if re.search(re.escape(leaf).replace("\\.", "[.]"), cmd, re.I):
            return True
        # Percent-encoded or dot-padded forms of the same leaf.
        squashed = re.sub(r"[^A-Za-z0-9]", "", leaf).lower()
        if squashed and squashed in re.sub(r"[^A-Za-z0-9]", "", cmd).lower():
            return True
    return False


def is_anchored(assertion, canary, *, proof_kinds=None, command=None,
                verdict_method=None, signatures=None) -> tuple:
    """(anchored, why).

    `proof_kinds` comes from the class table. With none supplied this is the
    original canary rule exactly, so an unknown class cannot become verifiable
    by accident.
    """
    kinds = [str(k) for k in (proof_kinds or [])]
    if not kinds:
        ok = anchored_echo(assertion, canary)
        return ok, ("canary in the assertion" if ok
                    else "no proof kind known and no canary in the assertion")

    if "echo" in kinds and anchored_echo(assertion, canary):
        return True, "echo: the injected canary is required by the assertion"
    if "oob" in kinds and anchored_oob(assertion, canary):
        return True, "oob: the sink marker carries this run's canary"
    if "timing" in kinds and anchored_timing(assertion, verdict_method):
        return True, "timing: the scaled-payload re-run confirmed the delay scales"
    if "file_content" in kinds and anchored_file_content(assertion, command, signatures):
        return True, ("file_content: the assertion is a known content signature "
                      "and the command requested that file")
    if _declared(assertion, canary):
        return True, "the assertion declares itself anchored with this run's canary"

    # Say which kind was expected — "not anchored" with no reason is what made
    # this impossible to diagnose from a run's trace.
    return False, ("no anchor for proof kind(s) %s: %s" % (
        ",".join(kinds),
        "assertion carries neither this run's canary, a confirmed timing "
        "re-run, nor a content signature the command asked for"))


# ── showing the proof that was accepted ─────────────────────────────────────
#
# "verified: true" with nothing to look at is the same gap as "anchored:
# false" with no reason. An operator reading a stored PoC needs to see the
# EVIDENCE the platform accepted — the bytes that matched, where they came
# from, and which rule let them count — or the verdict has to be taken on
# faith and cannot be reviewed, disputed, or put in a report.

_PROOF_CONTEXT = 90          # characters either side of the match
_PROOF_MAX = 400             # hard cap on what is carried into a record


def matched_span(assertion, output) -> dict:
    """What in the output actually satisfied the assertion.

    Returns {found, text, start, end}. `found` False means nothing matched —
    which is a real answer, not an empty string, because a verdict that passed
    on `default_truthy` matched NOTHING and that is worth seeing.
    """
    out = str(output or "")
    rx = str((assertion or {}).get("expect_regex") or "")
    if not rx or not out:
        return {"found": False, "text": "", "start": None, "end": None}
    try:
        m = re.search(rx, out, re.I | re.S)
    except re.error:
        # A regex the platform could not compile cannot have matched; say so
        # rather than reporting "no match", which would look like a clean
        # negative result.
        return {"found": False, "text": "", "start": None, "end": None,
                "error": "assertion regex does not compile"}
    if not m:
        return {"found": False, "text": "", "start": None, "end": None}
    a = max(0, m.start() - _PROOF_CONTEXT)
    b = min(len(out), m.end() + _PROOF_CONTEXT)
    return {"found": True, "text": out[a:b][:_PROOF_MAX],
            "match": m.group(0)[:200], "start": m.start(), "end": m.end()}


def proof_record(*, assertion, output, command, verdict_method, anchored,
                 anchor_why, proof_kinds=None, elapsed_seconds=None,
                 canary=None) -> dict:
    """The evidence the platform accepted, in a shape an operator can review.

    Deliberately includes the NEGATIVE cases: a record is written whether or
    not the run verified, because "why did this not count" is the question
    asked most often, and the answer used to exist only as a boolean.
    """
    kinds = [str(k) for k in (proof_kinds or [])]
    span = matched_span(assertion, output)
    rec = {
        "accepted": bool(anchored),
        "method": str(verdict_method or "") or None,
        "anchor": str(anchor_why or "") or None,
        "proof_kinds": kinds,
        "assertion": {k: v for k, v in (assertion or {}).items()
                      if k in ("expect_regex", "min_seconds", "max_seconds",
                               "expect_shell", "cve_anchored")},
        "matched": span,
        "canary_present": bool(canary and canary in str(output or "")),
        "elapsed_seconds": elapsed_seconds,
        "command_excerpt": str(command or "")[:300],
    }
    # What KIND of evidence this is, in words, so a report does not have to
    # decode the method name.
    if "file_content" in kinds and span.get("found"):
        rec["kind"] = "file content"
        rec["note"] = ("content only the real file has, and the command asked "
                       "for that file")
    elif "oob" in kinds and span.get("found"):
        rec["kind"] = "out-of-band callback"
        rec["note"] = "the sink recorded this run's canary"
    elif "timing" in kinds and (assertion or {}).get("min_seconds"):
        rec["kind"] = "timing"
        rec["note"] = ("the delay scaled with the payload on a second run"
                       if str(verdict_method or "").startswith("latency_confirmed")
                       else "a single elapsed, NOT confirmed by a scaled re-run")
    elif span.get("found"):
        rec["kind"] = "reflected marker"
        rec["note"] = "the injected canary came back in the response"
    else:
        rec["kind"] = "none"
        rec["note"] = ("nothing in the output matched the assertion — the "
                       "verdict did not come from a match")
    return rec
