"""Verify what a scan agent SAYS against what the scans actually recorded.

The models that write agent narrative are the same ones that produced
`smb-enum-links` (a plausible nmap script that does not exist), `smb
proliferateate`, and a sentence of prose in a script field. Nothing checked
their prose, so a fabricated port or CVE would reach a report unchallenged.

DELIBERATELY DETERMINISTIC. Claims are extracted with regexes and checked with
SQL — no second model is asked to judge the first. Using an LLM to verify an LLM
adds a second thing that can hallucinate, and the checkable claims (ports, CVEs,
services, hosts) have exact database answers.

WHAT THIS DOES NOT DO
---------------------
It catches FABRICATION, not wrongness. A claim about a port a scan did record is
"supported" even if the service fingerprint behind it is wrong. That is still the
failure worth catching: an invented finding in a client report is expensive, a
mislabelled one is ordinary scanning error.

It also cannot prove a negative. An unsupported claim may be true but unrecorded
— an agent reading tool output that was never ingested. Hence `unsupported`
rather than `false`, and hence the ingestion bug found earlier (23 ports seen, 0
stored) mattering here: with ingestion broken, every claim looks unsupported.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger("agent_claims")

# ── Extraction ──────────────────────────────────────────────────────────────
#
# Patterns are deliberately conservative. A missed claim costs nothing; a
# spurious one sends the operator to verify something the agent never said.

_CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)

# "port 3306", "port 3306/tcp", ":3306", "3306/tcp open"
_PORT_RE = re.compile(
    r"(?:\bport\s+(\d{1,5})\b"
    r"|\b(\d{1,5})/(?:tcp|udp)\b"
    r"|(?<![\w.])[:](\d{2,5})\b(?=\s|$|[,.;)]))",
    re.I,
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Only service names the KB knows; matching arbitrary words produces noise.
def _service_pattern(vocab) -> Optional[re.Pattern]:
    names = sorted({v for v in vocab if len(v) > 2}, key=len, reverse=True)
    if not names:
        return None
    return re.compile(r"\b(" + "|".join(re.escape(n) for n in names) + r")\b", re.I)


def extract_claims(text: str, service_vocab=None) -> List[Dict]:
    """Checkable factual assertions in agent prose.

    Returns dicts of {kind, value, context}. Anything not mechanically
    verifiable — judgements, next steps, advice — is deliberately ignored.
    """
    claims: List[Dict] = []
    if not text:
        return claims

    # Sentence- or line-bounded, NOT a character window.
    #
    # A ±45-char window bled severity between neighbouring sentences: in testing,
    # a host claim inherited "root shell" from the sentence before it and was
    # scored as an access finding. Severity is a property of the statement the
    # claim appears in, so the statement is the right unit.
    #
    # Split on sentence enders AND newlines, because agent notes are frequently
    # bullet lists and JSON fragments with no full stops at all — a
    # sentence-only split would return the entire blob for those.
    _bounds = [0] + [m.end() for m in re.finditer(r"(?<=[.!?])\s+|\n+", text)] + [len(text)]

    def _ctx(m) -> str:
        start = max((b for b in _bounds if b <= m.start()), default=0)
        end = min((b for b in _bounds if b >= m.end()), default=len(text))
        # A pathologically long "sentence" (unpunctuated log dump) still gets
        # bounded, or one claim would carry thousands of characters of context.
        seg = text[start:end]
        if len(seg) > 400:
            rel = m.start() - start
            seg = seg[max(0, rel - 120):rel + 160]
        return re.sub(r"\s+", " ", seg).strip()

    for m in _CVE_RE.finditer(text):
        claims.append({"kind": "cve", "value": m.group(0).upper(), "context": _ctx(m)})

    for m in _PORT_RE.finditer(text):
        raw = m.group(1) or m.group(2) or m.group(3)
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if not (1 <= port <= 65535):
            continue
        claims.append({"kind": "port", "value": port, "context": _ctx(m)})

    for m in _IPV4_RE.finditer(text):
        octets = m.group(0).split(".")
        if all(o.isdigit() and int(o) <= 255 for o in octets):
            claims.append({"kind": "host", "value": m.group(0), "context": _ctx(m)})

    if service_vocab:
        pat = _service_pattern(service_vocab)
        if pat:
            for m in pat.finditer(text):
                claims.append({"kind": "service", "value": m.group(1).lower(),
                               "context": _ctx(m)})

    # De-duplicate on (kind, value), keeping the first context seen.
    seen, out = set(), []
    for c in claims:
        key = (c["kind"], str(c["value"]).lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# ── Verification ────────────────────────────────────────────────────────────


def _text_columns(cur) -> Dict[str, List[str]]:
    """Which searchable text columns each findings-ish table actually has.

    The CVE check originally hard-coded `title` and `description`; neither
    findings nor vulns has `description` in this schema, so the query errored and
    aborted the transaction. Discovering columns keeps this working across schema
    drift instead of failing loudly on the next rename.
    """
    out: Dict[str, List[str]] = {}
    try:
        cur.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            " WHERE table_schema='public' AND table_name IN ('findings','vulns') "
            "   AND data_type IN ('text','character varying')")
        for row in cur.fetchall():
            t = row["table_name"] if isinstance(row, dict) else row[0]
            c = row["column_name"] if isinstance(row, dict) else row[1]
            out.setdefault(t, []).append(c)
    except Exception as e:
        logger.debug("could not introspect text columns: %s", e)
    return out



def _coverage(cur, ip: Optional[str]) -> Dict[str, bool]:
    """Can the database answer questions of each kind at all?

    THE DISTINCTION THAT MATTERS. "The scan recorded 23 ports and none was
    31337" is evidence of absence. "No ports were recorded for this host" is
    absence of evidence, and calling that unsupported is a lie that reads as a
    finding.

    Today's ingestion bug made the difference concrete: a scan found 23 ports and
    stored none of them, so every true claim would have been reported as
    unsupported. Coverage is checked first so that failure mode surfaces as
    "cannot verify" instead.
    """
    cov = {"port": False, "service": False, "host": False, "cve": False}
    try:
        if ip:
            cur.execute(
                "SELECT 1 FROM ports p JOIN assets a ON a.id = p.asset_id "
                " WHERE host(a.ip) = %s LIMIT 1", (ip,))
        else:
            cur.execute("SELECT 1 FROM ports LIMIT 1")
        has_ports = cur.fetchone() is not None
        cov["port"] = cov["service"] = has_ports
    except Exception as e:
        logger.debug("coverage: ports unavailable (%s)", e)
    try:
        cur.execute("SELECT 1 FROM assets LIMIT 1")
        cov["host"] = cur.fetchone() is not None
    except Exception as e:
        logger.debug("coverage: assets unavailable (%s)", e)
    for table in ("findings", "vulns"):
        try:
            cur.execute(f"SELECT 1 FROM {table} LIMIT 1")
            if cur.fetchone() is not None:
                cov["cve"] = True
                break
        except Exception:
            continue
    return cov


def verify_claims(cur, claims: List[Dict], ip: Optional[str] = None) -> List[Dict]:
    """Check each claim against recorded scan data.

    `cur` is an open cursor; the caller owns the connection. `ip` scopes port and
    service checks to one host when known — without it, a claim is supported if
    ANY scanned host matches, which is weaker but avoids false alarms on
    multi-target sessions.
    """
    text_cols = _text_columns(cur)
    cov = _coverage(cur, ip)
    results = []
    for c in claims:
        kind, value = c["kind"], c["value"]
        supported, detail = False, ""
        # SAVEPOINT per claim. Postgres aborts the WHOLE transaction on any
        # error, so one bad query poisons every check after it — which is
        # exactly what happened: the CVE lookup assumed a `description` column
        # that does not exist, and every subsequent claim came back unsupported,
        # including ports that were plainly recorded. Containing each check
        # means a schema surprise costs one claim, not the entire report.
        try:
            cur.execute("SAVEPOINT claim_sp")
        except Exception:
            pass
        try:
            if kind == "port":
                if ip:
                    cur.execute(
                        "SELECT p.service FROM ports p JOIN assets a ON a.id = p.asset_id "
                        " WHERE p.port = %s AND host(a.ip) = %s LIMIT 1", (value, ip))
                else:
                    cur.execute("SELECT service FROM ports WHERE port = %s LIMIT 1", (value,))
                row = cur.fetchone()
                supported = row is not None
                if row:
                    detail = f"recorded as {row['service'] or 'unknown service'}"

            elif kind == "service":
                if ip:
                    cur.execute(
                        "SELECT p.port FROM ports p JOIN assets a ON a.id = p.asset_id "
                        " WHERE lower(p.service) = %s AND host(a.ip) = %s LIMIT 1", (value, ip))
                else:
                    cur.execute("SELECT port FROM ports WHERE lower(service) = %s LIMIT 1",
                                (value,))
                row = cur.fetchone()
                supported = row is not None
                if row:
                    detail = f"recorded on port {row['port']}"

            elif kind == "host":
                cur.execute("SELECT 1 FROM assets WHERE host(ip) = %s LIMIT 1", (value,))
                supported = cur.fetchone() is not None

            elif kind == "cve":
                # Search every text column those tables actually have — CVEs land
                # in different fields depending on which tool reported them.
                for table, cols in (text_cols or {}).items():
                    if supported:
                        break
                    if not cols:
                        continue
                    where = " OR ".join(f"{c} ILIKE %s" for c in cols)
                    cur.execute(f"SELECT 1 FROM {table} WHERE {where} LIMIT 1",
                                tuple(f"%{value}%" for _ in cols))
                    if cur.fetchone():
                        supported = True
                        detail = f"referenced in {table}"
            try:
                cur.execute("RELEASE SAVEPOINT claim_sp")
            except Exception:
                pass
        except Exception as e:
            logger.debug("claim check failed (%s %s): %s", kind, value, e)
            detail = f"could not be checked: {e}"
            # Undo the aborted statement so the next claim starts clean.
            try:
                cur.execute("ROLLBACK TO SAVEPOINT claim_sp")
            except Exception:
                pass

        # Three states, not two. `unverifiable` is the honest answer when the
        # database cannot speak to the question — an unrecognised claim kind, or
        # no scan data of that kind at all. Reporting those as "unsupported"
        # would manufacture findings out of missing coverage.
        reason = None
        if supported:
            verdict = "supported"
        elif kind not in cov:
            verdict, reason = "unverifiable", "unknown_kind"
            detail = detail or f"no way to check a {kind!r} claim against scan data"
        elif not cov.get(kind):
            # No data of this kind AT ALL. Distinguished from the other reasons
            # because a run that produced nothing is a different problem from a
            # claim that cannot be expressed in the schema — see run_failure below.
            verdict, reason = "unverifiable", "no_coverage"
            detail = detail or (
                f"no {kind} data recorded{' for ' + ip if ip else ''} — absence of "
                f"evidence, not evidence of absence")
        elif detail.startswith("could not be checked"):
            verdict, reason = "unverifiable", "check_error"
        else:
            verdict = "unsupported"

        results.append({**c, "verdict": verdict,
                        "unverifiable_reason": reason,
                        # Kept for callers written against the old shape; only
                        # a genuine contradiction now counts as not-supported.
                        "supported": verdict == "supported",
                        "detail": detail})
    return results



# ── LLM-assisted extraction ─────────────────────────────────────────────────
#
# The regexes above catch tokens: ports, CVEs, IPs, known service names. They
# cannot catch "the database was reachable without a password" — a real,
# checkable assertion with no token to match.
#
# THE MODEL PROPOSES, SQL DECIDES. An LLM verdict on whether a claim is true
# would be circular (we are auditing LLM output) and unreliable — measured on the
# simpler task of naming real tools, gemma4 was wrong 7% of the time and qwen3.8
# 29%. So the model is used only to widen extraction: everything it proposes with
# a checkable kind still goes through verify_claims, where the database decides.
# A missed claim is cheap; a fabrication cleared by a model is not, and this
# arrangement makes the latter impossible.
#
# Claims it finds that are NOT mechanically checkable are not discarded either —
# they are routed to manual follow-up rather than silently dropped or, worse,
# adjudicated by the model.

_LLM_CLAIM_PROMPT = """You are extracting factual assertions from a penetration-test agent's notes.

List every SPECIFIC, CHECKABLE assertion about what was found. Do NOT judge whether
any of them is true — something else verifies them.

Return ONLY a JSON object:
{"claims":[{"kind":"port|cve|host|service|other","value":"<the specific thing>","assertion":"<what is claimed about it, one short phrase>"}]}

Rules:
- kind "port" -> value is the port number alone, e.g. "3306"
- kind "cve" -> value is the identifier, e.g. "CVE-2007-2447"
- kind "host" -> value is the IP or hostname
- kind "service" -> value is the service name, e.g. "mysql"
- kind "other" -> anything checkable that fits none of the above, such as a
  writable share, a disabled control, or a recovered credential. Put the subject
  in value.
- Skip opinions, recommendations, next steps and anything vague.
- If the notes contain no checkable assertion, return {"claims":[]}.

NOTES:
"""


def llm_extract_claims(text: str, query_fn, model: Optional[str] = None) -> List[Dict]:
    """Ask a model to propose claims the regexes cannot see.

    `query_fn(prompt, model=...)` returns the raw model response. Any failure
    yields [] — extraction is an enrichment, and losing it must never fail the
    verification that already worked.
    """
    if not text or not text.strip() or query_fn is None:
        return []
    try:
        raw = query_fn(_LLM_CLAIM_PROMPT + text[:12000], model=model)
    except Exception as e:
        logger.warning("LLM claim extraction failed (%s) — regex claims stand alone", e)
        return []

    body = raw.get("response") if isinstance(raw, dict) else raw
    obj = _first_json_object(body or "")
    if not isinstance(obj, dict):
        logger.warning("LLM claim extraction returned no usable JSON")
        return []

    out = []
    for c in (obj.get("claims") or []):
        if not isinstance(c, dict):
            continue
        kind = str(c.get("kind") or "other").strip().lower()
        value = str(c.get("value") or "").strip()
        if not value or len(value) > 120:
            continue
        if kind == "port":
            digits = re.sub(r"\D", "", value)
            if not digits or not (1 <= int(digits) <= 65535):
                continue
            value = int(digits)
        elif kind not in ("cve", "host", "service", "other"):
            kind = "other"
        out.append({
            "kind": kind,
            "value": value,
            "context": str(c.get("assertion") or "")[:200],
            "source": "llm",
        })
    return out


def _first_json_object(text: str) -> Optional[Dict]:
    """First balanced {...} in the text, tolerating prose and fences."""
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    try:
        import json as _json
        return _json.loads(t)
    except Exception:
        pass
    import json as _json
    start = t.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(t)):
            ch = t[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return _json.loads(t[start:i + 1])
                    except Exception:
                        break
        start = t.find("{", start + 1)
    return None


def merge_claims(regex_claims: List[Dict], llm_claims: List[Dict]) -> List[Dict]:
    """Regex claims win on collision — they matched literal text, not inference."""
    out = list(regex_claims)
    seen = {(c["kind"], str(c["value"]).lower()) for c in regex_claims}
    for c in llm_claims:
        key = (c["kind"], str(c["value"]).lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# ── Notability ──────────────────────────────────────────────────────────────
#
# Verification alone is negative-only: it reports what cannot be supported and
# files everything else as "fine". But a SUPPORTED claim of a root shell or
# recovered credentials is the most important line in the report, and it was
# being passed over in silence.
#
# Scoring is deterministic keyword matching against the claim's surrounding
# context. It is a PRIORITISATION signal, not a judgement of truth — the truth
# question is answered by `supported`, which comes from the database.

_NOTABLE_PATTERNS = (
    # (weight, category, regex) — highest weight wins for a given claim.
    (5, "access",         r"\b(root|SYSTEM|administrator)\s+(shell|access|privileg|account)"),
    (5, "access",         r"\b(reverse|bind)\s*shell\b|\bgot\s+(a\s+)?shell\b|\brce\b"),
    (5, "access",         r"\bremote code execution\b|\bcommand execution\b"),
    (5, "backdoor",       r"\bbackdoor(ed)?\b|\bimplant\b|\balready compromised\b"),
    (4, "credentials",    r"\bcredential|password|hash(es)?\b|\bcracked\b|\bplaintext\b"),
    (4, "credentials",    r"\bdefault (creds|credentials|password)\b|\banonymous (login|access)\b"),
    (4, "unauthenticated", r"\bunauthenticated\b|\bno (auth|authentication|password)\b"),
    (4, "unauthenticated", r"\bworld[- ]readable\b|\bpublicly (accessible|readable)\b"),
    (3, "data-exposure",  r"\bexfiltrat|\bdump(ed)?\b|\bdisclos(ure|ed)\b|\bleak(ed|s)?\b"),
    (3, "lateral",        r"\bpivot|lateral movement|password reuse\b"),
    (3, "critical-vuln",  r"\bcritical\b|\bexploitable\b|\bproof[- ]of[- ]concept\b"),
    (2, "privesc",        r"\bprivilege escalation|privesc|suid\b|\bsudo\b"),
)


def score_notability(claim: Dict) -> Dict:
    """Attach {notable, notable_score, notable_reason} to a verified claim.

    Priority is severity CROSSED WITH support, because the two combine in a way
    neither shows alone:

      supported + high severity  -> act on this
      unsupported + high severity -> verify first; a big claim with no evidence
                                     behind it is the most expensive kind to put
                                     in a report
      unsupported + low severity  -> minor, likely a stray number in prose
    """
    ctx = (claim.get("context") or "")
    best_w, best_cat = 0, None
    for weight, category, pattern in _NOTABLE_PATTERNS:
        if weight > best_w and re.search(pattern, ctx, re.I):
            best_w, best_cat = weight, category

    if best_w == 0:
        return {**claim, "notable": False, "notable_score": 0, "notable_reason": None}

    supported = claim.get("supported")
    if supported:
        reason = f"{best_cat}: supported by recorded scan data"
        score = best_w
    else:
        # An unsupported high-severity claim outranks a supported one: it is
        # both important and unevidenced, which is the combination that damages
        # a report.
        reason = f"{best_cat}: HIGH-IMPACT CLAIM WITH NO SUPPORTING SCAN DATA"
        score = best_w + 1
    return {**claim, "notable": True, "notable_score": score, "notable_reason": reason}


def summarise(results: List[Dict]) -> Dict:
    """Counts, the unsupported claims, and the notable ones.

    Two separate axes deliberately: `unsupported` answers "can this be backed
    up", `notable` answers "does this matter". A claim can be either, both, or
    neither, and conflating them would hide the worst case — an important claim
    with nothing behind it.
    """
    # Derive a verdict for results that predate the three-state model (or come
    # from a caller that only set `supported`), so they are counted rather than
    # silently falling into neither bucket.
    results = [score_notability({**r, "verdict": r.get("verdict") or
                                 ("supported" if r.get("supported") else "unsupported")})
               for r in results]
    unsupported = [r for r in results if r.get("verdict") == "unsupported"]
    unverifiable = [r for r in results if r.get("verdict") == "unverifiable"]
    notable = sorted((r for r in results if r.get("notable")),
                     key=lambda r: -r["notable_score"])
    # Manual follow-up: everything a human must resolve because the database
    # cannot — either it has no answer, or the claim is important and the answer
    # was "no". Sorted so the consequential ones come first.
    follow_up = sorted(
        [r for r in results
         if r.get("verdict") == "unverifiable"
         or (r.get("verdict") == "unsupported" and r.get("notable"))],
        key=lambda r: -(r.get("notable_score") or 0),
    )
    by_kind: Dict[str, Dict[str, int]] = {}
    for r in results:
        b = by_kind.setdefault(r["kind"], {"total": 0, "unsupported": 0})
        b["total"] += 1
        if not r["supported"]:
            b["unsupported"] += 1
    # A run that produced no data looks, claim by claim, like a series of small
    # mysteries. In aggregate it is one big finding. Today's ingestion bug is the
    # case in point: a scan found 23 ports and stored none, so every true claim
    # would have come back unverifiable and the operator would have been left
    # puzzling over each one instead of being told the run had failed.
    no_coverage = [r for r in results if r.get("unverifiable_reason") == "no_coverage"]
    probable_run_failure = bool(
        no_coverage and len(no_coverage) >= max(2, int(0.5 * len(results)))
    )
    kinds_missing = sorted({r["kind"] for r in no_coverage})
    run_failure_hint = None
    if probable_run_failure:
        run_failure_hint = (
            f"{len(no_coverage)} of {len(results)} claims could not be checked because no "
            f"{'/'.join(kinds_missing)} data was recorded at all. That usually means the scan "
            f"or its ingestion failed rather than the agent inventing things — check the job's "
            f"ingest stats before treating any of this as fabrication."
        )

    return {
        "claims_checked": len(results),
        "probable_run_failure": probable_run_failure,
        "run_failure_hint": run_failure_hint,
        "unsupported_count": len(unsupported),
        "by_kind": by_kind,
        "unsupported": unsupported[:50],
        "unverifiable_count": len(unverifiable),
        "unverifiable": unverifiable[:50],
        "notable_count": len(notable),
        "notable": notable[:50],
        "manual_follow_up_count": len(follow_up),
        "manual_follow_up": follow_up[:50],
    }
