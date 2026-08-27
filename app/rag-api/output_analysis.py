"""Read tool output for RESULTS, not just for presence of bytes.

WHY THIS EXISTS
---------------
A single crackmapexec run against 192.168.1.150 produced six distinct security
facts:

    SMB ... [*] Unix (name:METASPLOITABLE) (domain:localdomain) (signing:False) (SMBv1:True)
    SMB ... [+] localdomain\\:
    SMB ... [+] Enumerated shares
    SMB ... Share           Permissions     Remark
    SMB ... -----           -----------     ------
    SMB ... print$                          Printer Drivers
    SMB ... tmp             READ,WRITE      oh noes!
    SMB ... opt
    SMB ... IPC$                            IPC Service (metasploitable server (Samba 3.0.20-Debian))
    SMB ... ADMIN$                          IPC Service (metasploitable server (Samba 3.0.20-Debian))

SMBv1 enabled, SMB signing disabled, a null session accepted, five shares — one
of them WORLD-WRITABLE — the hostname, and the Samba version. Measured against
the database afterwards: **none of it was stored.** Zero rows in `vulns`,
`recon_findings`, `credential_findings`, and no asset carried the hostname. The
execution was recorded as "produced output" and that was the end of it.

So "the run produced output" is not the same claim as "we have the results", and
until now only the first was ever checked.

THE HEADER TRAP
---------------
`Share  Permissions  Remark` is a COLUMN HEADER, and the row under it is
`-----  -----------  ------`. A naive line-wise extractor turns those into two
shares named "Share" and "-----", and a truncated read of the header turns
"Permissions" into a share called "Pe". Junk assets look exactly like real ones
once stored, so the table parser locates the header, skips it and its rule line,
and refuses any name that IS a header word. `test_output_analysis.py` pins that
with the real output.

RULES FIRST, MODEL SECOND
-------------------------
Extraction is deterministic: the same output yields the same facts, which is
what makes a fingerprint stable and a diff meaningful. An LLM pass is useful for
the leftovers — `unclear` output nobody wrote an extractor for — and that is
where it belongs, downstream of this, not in place of it.
"""
import re

__all__ = ["analyse_output", "extract_smb", "OUTPUT_INDICATORS"]

# Lines that are structure, never data. The share-table separator is the reason
# this exists at all.
_HEADER_WORDS = {
    "share", "shares", "permissions", "remark", "remarks", "comment", "disk",
    "type", "name", "user", "users", "group", "groups", "port", "state",
    "service", "version",
}
_SEPARATOR_RE = re.compile(r"^[-=_\s|+]+$")

# crackmapexec/nxc prefix each line with `PROTO  host  port  hostname  `. The
# payload is everything after it, and stripping it is what lets one parser read
# both crackmapexec and smbmap.
_CME_PREFIX = re.compile(
    r"^(?P<proto>SMB|LDAP|WINRM|SSH|FTP|RDP|MSSQL)\s+"
    r"(?P<host>\S+)\s+(?P<port>\d+)\s+(?P<netbios>\S+)\s+(?P<body>.*)$")


def _payload_lines(output):
    """(body, raw) per line, with the crackmapexec prefix removed."""
    out = []
    for raw in (output or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m = _CME_PREFIX.match(line.strip())
        out.append((m.group("body").rstrip() if m else line.strip(), line))
    return out


def _is_structure(name):
    """True for a header cell or a rule line — never a real value."""
    n = (name or "").strip().lower()
    return (not n) or n in _HEADER_WORDS or bool(_SEPARATOR_RE.match(n))


# ── SMB ─────────────────────────────────────────────────────────────────────

_SMB_HOSTINFO = re.compile(
    r"\((?:name):(?P<name>[^)]*)\)\s*\((?:domain):(?P<domain>[^)]*)\)\s*"
    r"\((?:signing):(?P<signing>[^)]*)\)\s*\((?:SMBv1):(?P<smbv1>[^)]*)\)", re.I)
_SMB_OS = re.compile(r"\[\*\]\s*(?P<os>Windows[^(]*|Unix[^(]*)\(", re.I)
# `[+] domain\user:pass` — an EMPTY user and pass is an accepted null session.
_SMB_AUTH = re.compile(r"\[\+\]\s*(?P<domain>[^\\]*)\\(?P<user>[^:]*):(?P<pw>.*)$")
_SAMBA_VER = re.compile(r"(Samba\s+[0-9][0-9A-Za-z.\-]*)", re.I)
_PERM_RE = re.compile(r"\b(READ,WRITE|READ ONLY|WRITE ONLY|READ|WRITE|NO ACCESS)\b", re.I)


def extract_smb(output):
    """Facts from crackmapexec / nxc / smbmap SMB output.

    Returns {"facts": {...}, "shares": [...], "notable": [...]}.
    Every `notable` carries the line it came from, because a finding whose
    evidence is not quotable cannot be triaged.
    """
    facts, shares, notable = {}, [], []
    in_table = False

    for body, raw in _payload_lines(output):
        m = _SMB_HOSTINFO.search(body)
        if m:
            facts["netbios_name"] = m.group("name").strip()
            facts["domain"] = m.group("domain").strip()
            facts["signing"] = m.group("signing").strip().lower() == "true"
            facts["smbv1"] = m.group("smbv1").strip().lower() == "true"
            os_m = _SMB_OS.search(body)
            if os_m:
                facts["os"] = os_m.group("os").strip()
            if facts["smbv1"]:
                notable.append({
                    "id": "smb_v1_enabled", "severity": "medium",
                    "title": "SMBv1 is enabled",
                    "detail": "SMBv1 is deprecated and exposes the host to "
                              "known remote-code-execution families.",
                    "evidence": raw.strip()})
            if facts["signing"] is False:
                notable.append({
                    "id": "smb_signing_disabled", "severity": "medium",
                    "title": "SMB signing is disabled",
                    "detail": "Unsigned SMB permits relay and man-in-the-middle "
                              "against authenticated sessions.",
                    "evidence": raw.strip()})
            continue

        ver = _SAMBA_VER.search(body)
        if ver and "samba_version" not in facts:
            facts["samba_version"] = ver.group(1).strip()

        auth = _SMB_AUTH.match(body)
        if auth and "enumerated" not in body.lower():
            user = auth.group("user").strip()
            pw = auth.group("pw").strip()
            if not user and not pw:
                facts["null_session"] = True
                notable.append({
                    "id": "smb_null_session", "severity": "high",
                    "title": "SMB null session accepted",
                    "detail": "The host authenticated an empty username and "
                              "password, so share and account enumeration "
                              "needs no credentials.",
                    "evidence": raw.strip()})
            else:
                facts.setdefault("authenticated_as", []).append(
                    {"domain": auth.group("domain").strip(), "username": user})
            continue

        # ── the share table ──
        low = body.lower()
        if low.startswith("share") and "perm" in low:
            in_table = True          # this line is the HEADER, not a share
            continue
        if in_table:
            if _SEPARATOR_RE.match(body):
                continue             # the ----- rule line
            cols = re.split(r"\s{2,}", body.strip())
            name = cols[0].strip() if cols else ""
            if _is_structure(name):
                continue
            if not re.match(r"^[\w$.\-]+$", name):
                in_table = False     # left the table
                continue
            perm_m = _PERM_RE.search(body)
            perms = perm_m.group(1).upper() if perm_m else ""
            remark = ""
            if len(cols) > 1:
                tail = [c for c in cols[1:] if not _PERM_RE.fullmatch(c.strip())]
                remark = " ".join(t.strip() for t in tail).strip()
            shares.append({"name": name, "permissions": perms, "remark": remark})
            if "WRITE" in perms:
                notable.append({
                    "id": "smb_writable_share", "severity": "high",
                    "title": f"SMB share '{name}' is writable",
                    "detail": f"Permissions {perms} on '{name}'. A writable "
                              "share allows file drop, and combined with a null "
                              "session requires no credentials at all.",
                    "evidence": raw.strip()})

    if shares and facts.get("null_session"):
        notable.append({
            "id": "smb_anonymous_share_enumeration", "severity": "medium",
            "title": f"{len(shares)} share(s) enumerated without credentials",
            "detail": "Share names and remarks disclose host layout and "
                      "software versions to an unauthenticated caller.",
            "evidence": ", ".join(s["name"] for s in shares)})
    return {"facts": facts, "shares": shares, "notable": notable}


# ── generic indicators, counted from real stored output ─────────────────────
# Each count below is how many of the 1,348 stored executions the pattern
# matched when it was written, so none of these is a guess.
OUTPUT_INDICATORS = (
    ("open_ports", re.compile(r"^\s*\d+/(?:tcp|udp)\s+open", re.M), 189),
    ("success_markers", re.compile(r"\[\+\]"), 170),
    ("vuln_references", re.compile(r"OSVDB|CVE-\d{4}-\d+", re.I), 56),
    ("accounts", re.compile(r"user:\[|Account:|Local User", re.I), 47),
    ("smb_mapping", re.compile(r"Mapping:\s*OK", re.I), 46),
    ("credentials", re.compile(r"valid password found|successful login|"
                               r"login:\s*\S+\s+password:", re.I), 15),
    ("ssh_algorithms", re.compile(r"\((?:kex|key|enc|mac)\)"), 17),
)

# Output that POSITIVELY confirms nothing is there. Distinguishing this from
# "we don't know" is the difference between a closed service and a blind spot.
EMPTY_MARKERS = re.compile(
    r"0 hosts up|Timeout: No Response|no shares|0 valid password|"
    r"nothing found|no hosts found|0 results", re.I)

# Below this, output is a banner or a version string rather than a result.
_BANNER_BYTES = 200

EXTRACTORS = {
    "crackmapexec": extract_smb, "nxc": extract_smb, "netexec": extract_smb,
    "smbmap": extract_smb, "smbclient": extract_smb,
}


def analyse_output(tool, output, exit_code=None):
    """What did this run actually find?

    verdict is one of:
      results_found   — extracted facts or a matched indicator
      confirmed_empty — the tool said, in its own words, that nothing is there
      banner_only     — it spoke, but only to identify itself
      unclear         — output exists and nothing here understands it. NOT
                        claimed as empty; this is the honest bucket, and the
                        queue an LLM pass should work from.
    """
    text = output or ""
    indicators = {}
    for name, pattern, _seen in OUTPUT_INDICATORS:
        n = len(pattern.findall(text))
        if n:
            indicators[name] = n

    extracted, notable, spec_used = {}, [], None
    fn = EXTRACTORS.get((tool or "").strip().lower())
    if fn and text.strip():
        try:
            extracted = fn(text)
            notable = list(extracted.get("notable", []))
        except Exception as exc:            # noqa: BLE001
            extracted = {"error": f"{type(exc).__name__}: {exc}"}

    # YAML extraction specs, for the tools no Python extractor covers.
    #
    # These two mechanisms were built separately and never joined, which is why
    # enum4linux-ng's 48 stored runs reported ZERO facts while a spec with four
    # notable rules sat in knowledge/extractors/ being read by nothing but the
    # username harvester. 95 of the 100 uninterpreted executions were
    # enum4linux/enum4linux-ng for exactly this reason.
    #
    # Deterministic regexes only here: an LLM pass belongs in the artifact queue,
    # not inside a function called once per execution in a review loop.
    cover = None
    if text.strip():
        try:
            import extractor_specs as _es
            spec = _es.spec_for(tool)
            if spec:
                spec_used = spec.get("_source_file")
                fields = _es.run_deterministic(spec, text)
                if fields:
                    extracted.setdefault("fields", {}).update(fields)
                    seen = {n.get("id") for n in notable}
                    for n in _es.notable_from(spec, fields):
                        if n["id"] not in seen:
                            seen.add(n["id"])
                            notable.append(n)
                # How much of the output the patterns did NOT consume — the
                # signal that this tool emitted something uncovered.
                cover = _es.coverage(spec, text)
        except Exception as exc:            # noqa: BLE001
            extracted.setdefault("spec_error", f"{type(exc).__name__}: {exc}")

    has_facts = bool(notable) or bool(extracted.get("shares")) \
        or bool(extracted.get("facts")) or bool(extracted.get("fields"))
    if has_facts or indicators:
        verdict = "results_found"
    elif EMPTY_MARKERS.search(text):
        verdict = "confirmed_empty"
    elif len(text.strip()) < _BANNER_BYTES:
        verdict = "banner_only"
    else:
        verdict = "unclear"

    return {
        "verdict": verdict,
        "exit_code": exit_code,
        "indicators": indicators,
        "extracted": extracted,
        "notable": notable,
        "notable_count": len(notable),
        "spec": spec_used,
        "coverage": cover,
        # A profiled tool whose patterns left substantial residual has emitted
        # something the profile does not cover — worth a new pattern.
        "uncovered": bool(cover and cover["residual_lines"] >= 4
                          and cover["coverage_pct"] < 85),
        "output_bytes": len(text),
        # An LLM pass is worth spending only where rules found nothing but
        # there is clearly something to read.
        "needs_llm_review": verdict == "unclear",
    }
