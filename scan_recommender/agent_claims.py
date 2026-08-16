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

    def _ctx(m) -> str:
        s = max(0, m.start() - 45)
        return re.sub(r"\s+", " ", text[s:m.end() + 45]).strip()

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


def verify_claims(cur, claims: List[Dict], ip: Optional[str] = None) -> List[Dict]:
    """Check each claim against recorded scan data.

    `cur` is an open cursor; the caller owns the connection. `ip` scopes port and
    service checks to one host when known — without it, a claim is supported if
    ANY scanned host matches, which is weaker but avoids false alarms on
    multi-target sessions.
    """
    text_cols = _text_columns(cur)
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

        results.append({**c, "supported": supported, "detail": detail})
    return results



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
    results = [score_notability(r) for r in results]
    unsupported = [r for r in results if not r["supported"]]
    notable = sorted((r for r in results if r.get("notable")),
                     key=lambda r: -r["notable_score"])
    by_kind: Dict[str, Dict[str, int]] = {}
    for r in results:
        b = by_kind.setdefault(r["kind"], {"total": 0, "unsupported": 0})
        b["total"] += 1
        if not r["supported"]:
            b["unsupported"] += 1
    return {
        "claims_checked": len(results),
        "unsupported_count": len(unsupported),
        "by_kind": by_kind,
        "unsupported": unsupported[:50],
        "notable_count": len(notable),
        "notable": notable[:50],
    }
