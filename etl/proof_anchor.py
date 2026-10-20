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
    """The original rule: the assertion requires the canary we injected.

    For an ECHO proof the canary IS the proof, so `_declared` alone does not
    stand here: an assertion may CARRY the canary as metadata while matching
    on something else entirely, and then the declaration is unfounded.

    Observed 2026-10-20 on CVE-2024-34070, stored as a verified PoC:

        command   = echo 'REFUSED: cannot provide exploit PoC'
        assertion = {"canary": "POCz2c556557da", "cve_anchored": true,
                     "expect_regex": "REFUSED"}

    The model declined to write an exploit, the refusal text became the
    command, an assertion was built that matches that text, and because the
    canary rode along in a sibling field `_declared` said "anchored". The run
    proved only that `echo` works.

    So: a non-empty regex that does not mention the canary REFUTES the
    declaration for this kind. An empty regex leaves nothing to contradict it
    (timing and file_content proofs legitimately carry no canary regex, and
    they are handled by their own anchors anyway).
    """
    if not canary:
        return False
    rx = _regex_of(assertion)
    if canary in rx:
        return True
    return _declared(assertion, canary) and not rx


def anchored_oob(assertion, canary) -> bool:
    """A sink marker carrying THIS run's canary.

    The canary is what makes it this run's callback rather than a stale one
    from a previous attempt against the same sink.
    """
    if not canary:
        return False
    rx = _regex_of(assertion)
    if not any(m in rx for m in _OOB_MARKERS):
        # No sink marker in the regex, so the declaration is all there is —
        # and it only stands when there is no regex to contradict it. An
        # assertion matching on something unrelated while CARRYING the canary
        # in a sibling field is the same unfounded self-declaration that let
        # `echo 'REFUSED: ...'` be stored as a verified PoC (see
        # anchored_echo). Same rule, same reason.
        return _declared(assertion, canary) and not rx
    return canary in rx or _declared(assertion, canary)


#: DB error fragments that only a database emits. A page can contain the words
#: "error" or "syntax"; it cannot contain MySQL's own parser message unless a
#: database produced it. Keyed by engine so the proof names which one answered.
#:
#: Deliberately conservative and literal: a loose pattern here would let a
#: generic 500 page anchor a SQLi proof, which is the failure mode this whole
#: file exists to prevent.
DB_ERROR_SIGNATURES = {
    "mysql": (
        "You have an error in your SQL syntax",
        "check the manual that corresponds to your MySQL server version",
        "supplied argument is not a valid MySQL result",
        "mysql_fetch_array()",
        "MySQLSyntaxErrorException",
    ),
    "postgres": (
        "PG::SyntaxError",
        "unterminated quoted string at or near",
        "syntax error at or near",
        "PSQLException",
    ),
    "mssql": (
        "Unclosed quotation mark after the character string",
        "Incorrect syntax near",
        "System.Data.SqlClient.SqlException",
    ),
    "oracle": (
        "ORA-00933",
        "ORA-01756",
        "quoted string not properly terminated",
    ),
    "sqlite": (
        "SQLite3::SQLException",
        "sqlite3.OperationalError",
        "unrecognized token:",
    ),
}


def db_error_engine(text) -> Optional[str]:
    """Which engine emitted this, or None. Used by the anchor and reportable."""
    t = str(text or "")
    if not t:
        return None
    for engine, sigs in DB_ERROR_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in t.lower():
                return engine
    return None


def anchored_error(assertion, command, canary=None) -> bool:
    """The assertion requires a DB parser error that the command provoked.

    The cheapest certain SQLi proof: one request. A database syntax error
    naming the engine proves attacker input reached the SQL parser — nothing
    but a database emits `You have an error in your SQL syntax`.

    Two halves, same reasoning as `anchored_file_content`: the assertion must
    require the signature, AND the command must carry something that would
    provoke it. A page that happens to contain the words is not proof, and a
    broken-quote payload with no assertion on the result proves nothing was
    observed.

    Why this matters here: the sqli class could only prove by `timing`, and
    the archive has 920 `latency_too_fast` rows — a SLEEP that returned
    instantly, i.e. the payload never reached the parser. An error-based proof
    answers the SAME question (did the input reach the parser?) in one request
    and with no dependence on how fast the target answers.
    """
    rx = _regex_of(assertion)
    if not rx:
        return False
    if db_error_engine(rx) is None:
        return False
    # The command has to contain a syntax-breaking payload. An unbalanced
    # quote or comment introducer is what provokes the parser; without one the
    # error was already there and is pre-existing state, not this exploit's
    # effect.
    cmd = str(command or "")
    if not cmd:
        return False
    provokers = ("'", '"', "--", "/*", ";", "%27", "%22")
    return any(p in cmd for p in provokers)


def anchored_boolean(assertion, command, canary=None) -> bool:
    """The assertion requires two responses to DIFFER.

    A boolean proof is a differential: `' AND 1=1--` and `' AND 1=2--` give
    different answers only if the database EVALUATED the expression. Two
    requests, deterministic, and — unlike timing — immune to a slow target or
    a WAF with a fixed delay, which are the two things that make a latency
    verdict unreliable and that TIMING_CONFIRM_DELTA_SEC exists to work
    around.

    Anchored on the DIFFERENTIAL, never on a single response. "The page
    rendered" is not evidence; "these two requests, differing only in a
    boolean, produced different output" is. So the assertion must declare
    both arms — a lone regex cannot anchor this kind, by construction.
    """
    a = assertion or {}
    diff = a.get("differential")
    if not isinstance(diff, dict):
        return False
    true_arm = diff.get("true")
    false_arm = diff.get("false")
    if not (true_arm and false_arm):
        return False
    # The arms must actually be different payloads: asserting that identical
    # requests differ is either a flake or a fabricated proof.
    if str(true_arm).strip() == str(false_arm).strip():
        return False
    return bool(diff.get("must_differ"))


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


#: Tools that actually reach the target. A command built only from shell
#: builtins contacts nothing, so whatever it "proves" came from this host.
_TARGET_CONTACT = (
    "curl", "wget", "nc ", "ncat", "netcat", "socat", "openssl s_client",
    "python", "python3", "perl", "ruby", "php", "java", "nmap", "masscan",
    "nuclei", "sqlmap", "ffuf", "gobuster", "feroxbuster", "katana", "httpx",
    "hydra", "medusa", "msfconsole", "msfvenom", "ssh ", "ftp ", "telnet",
    "smbclient", "redis-cli", "mysql", "psql", "mongo", "ldapsearch", "dig",
    "host ", "nslookup", "wfuzz", "arjun", "whatweb", "nikto", "zap-cli",
)


def proof_requires_target(command) -> bool:
    """Could this command have learned anything from the target?

    A PoC whose command never contacts the target cannot prove a
    vulnerability in it, whatever its assertion matches. `echo 'REFUSED: ...'`
    satisfies `expect_regex: "REFUSED"` perfectly and demonstrates nothing —
    it was stored as a verified PoC on 2026-10-20.

    Deliberately a WHITELIST of contacting tools rather than a blacklist of
    builtins: a new builtin would silently pass a blacklist, where a new tool
    missing from this list only costs a refusal the operator can see and fix.
    Fail-SAFE, not fail-open, because the output of this decides whether
    something is recorded as a proven exploit.

    Empty or unparseable command -> False: nothing is not a proof.
    """
    c = str(command or "").lower()
    if not c.strip():
        return False
    return any(t in c for t in _TARGET_CONTACT)


def is_anchored(assertion, canary, *, proof_kinds=None, command=None,
                verdict_method=None, signatures=None) -> tuple:
    """(anchored, why).

    `proof_kinds` comes from the class table. With none supplied this is the
    original canary rule exactly, so an unknown class cannot become verifiable
    by accident.
    """
    # No contact with the target, no proof about the target. Checked FIRST and
    # for every proof kind: an assertion cannot earn an anchor that the
    # command's own reach makes impossible. `command` is optional on this
    # signature, so an absent one skips the check rather than refusing — the
    # callers that decide "verified" all pass it.
    if command is not None and not proof_requires_target(command):
        return False, ("the command never contacts the target "
                       "(no request-issuing tool in it), so nothing it "
                       "matched can be evidence about the target")

    kinds = [str(k) for k in (proof_kinds or [])]
    if not kinds:
        ok = anchored_echo(assertion, canary)
        return ok, ("canary in the assertion" if ok
                    else "no proof kind known and no canary in the assertion")

    # Cheapest and most certain first. An error or boolean proof answers the
    # same question timing does — did the input reach the SQL parser? — in one
    # or two requests, with no dependence on how fast the target answers.
    if "error" in kinds and anchored_error(assertion, command, canary):
        return True, ("error: the assertion requires a %s parser error the "
                      "command provokes" % (db_error_engine(_regex_of(assertion)),))
    if "boolean" in kinds and anchored_boolean(assertion, command, canary):
        return True, ("boolean: the proof is a differential — two requests "
                      "differing only in a boolean produced different output")
    if "echo" in kinds and anchored_echo(assertion, canary):
        return True, "echo: the injected canary is required by the assertion"
    if "oob" in kinds and anchored_oob(assertion, canary):
        return True, "oob: the sink marker carries this run's canary"
    if "timing" in kinds and anchored_timing(assertion, verdict_method):
        return True, "timing: the scaled-payload re-run confirmed the delay scales"
    if "file_content" in kinds and anchored_file_content(assertion, command, signatures):
        return True, ("file_content: the assertion is a known content signature "
                      "and the command requested that file")
    # The generic self-declaration. It is the DESIGNED route for the proof
    # kinds where the canary cannot appear in the regex: a file read asserts
    # on content only the real file has (CLAUDE.md: a returning canary there
    # is a REFUTATION), and a blind-timing proof has nothing to reflect into.
    # For those, a content signature plus a declared canary is the correct
    # shape and must keep anchoring.
    #
    # For a REFLECTION kind it is not. If `echo` or `oob` is on the table and
    # neither anchor matched, the canary was supposed to be in the regex and
    # is not, so the declaration is claiming an anchor it does not have —
    # which is how `{"canary": "...", "cve_anchored": true,
    # "expect_regex": "REFUSED"}` came to be stored as a verified PoC.
    _reflection = any(k in kinds for k in ("echo", "oob"))
    if _declared(assertion, canary):
        if _reflection and _regex_of(assertion):
            return False, ("the assertion declares itself anchored with this "
                           "run's canary but matches on %r, which does not "
                           "contain it — for a reflection proof the canary IS "
                           "the proof" % (_regex_of(assertion)[:60],))
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
