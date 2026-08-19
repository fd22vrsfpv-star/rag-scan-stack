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

import re
from typing import Any, Dict, List, Optional

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


# ── Rule table ────────────────────────────────────────────────────────────
#
# `script` templates use {target} and {port}, which the dispatcher already
# substitutes. Priority follows the existing scan_recommendations convention:
# higher runs first, 50 is the default.

RULES: List[Dict[str, Any]] = [
    {
        "id": "smb_signing_disabled",
        "category": "smb",
        "pattern": r"signing\s*[:=]\s*(?:False|false|0|disabled)",
        "scanner": "nmap",
        "script": "nmap -p445 --script smb-security-mode,smb2-security-mode {target}",
        "title": "Confirm SMB signing is not required",
        "rationale": "SMB signing disabled permits relay attacks. Confirm and "
                     "record the exact security mode before relying on it.",
        "priority": 70,
    },
    {
        "id": "smbv1_enabled",
        "category": "smb",
        "pattern": r"SMBv1\s*[:=]\s*(?:True|true|1|enabled)",
        "scanner": "nmap",
        "script": "nmap -p445 --script smb-vuln-ms17-010,smb-vuln-ms08-067 {target}",
        "title": "Test SMBv1 host for known critical SMB vulnerabilities",
        "rationale": "SMBv1 is enabled, so the MS17-010/MS08-067 families are "
                     "worth checking directly rather than inferring from version.",
        "priority": 85,
    },
    {
        "id": "smb_shares",
        "category": "smb",
        "pattern": r"\b(IPC\$|ADMIN\$|C\$|\bsharename\b|Disk\s+Permissions)",
        "scanner": "smbmap",
        "script": "smbmap -H {target}",
        "title": "Enumerate SMB share permissions",
        "rationale": "Shares are exposed; map read/write access per share.",
        "priority": 65,
    },
    {
        "id": "anonymous_ftp",
        "category": "ftp",
        "pattern": r"(Anonymous\s+FTP\s+login\s+allowed|ftp-anon|anonymous\s+access\s+allowed)",
        "scanner": "nmap",
        "script": "nmap -p21 --script ftp-anon,ftp-syst {target}",
        "title": "Enumerate anonymous FTP contents",
        "rationale": "Anonymous FTP is permitted — list what is actually readable.",
        "priority": 75,
    },
    {
        "id": "nfs_export",
        "category": "nfs",
        "pattern": r"(/\S+\s+\*\s*$|nfs-showmount|Export\s+list\s+for)",
        "scanner": "showmount",
        "script": "showmount -e {target}",
        "title": "Enumerate NFS exports",
        "rationale": "An NFS export was referenced; confirm what is world-exported.",
        "priority": 65,
    },
    {
        "id": "snmp_public",
        "category": "snmp",
        "pattern": r"\b(community\s+string|public|private)\b.{0,30}\b(snmp)\b|snmp.{0,30}\bpublic\b",
        "scanner": "snmpwalk",
        "script": "snmpwalk -v2c -c public {target}",
        "title": "Walk SNMP with the default community string",
        "rationale": "A default community string was referenced — enumerate the MIB.",
        "priority": 60,
    },
    {
        "id": "ssh_version",
        "category": "ssh",
        "pattern": r"SSH-2\.0-\S+|OpenSSH[_ ]\d+\.\d+",
        "scanner": "ssh-audit",
        "script": "ssh-audit {target}",
        "title": "Audit SSH algorithms and key exchange",
        "rationale": "An SSH banner is present; audit ciphers/KEX rather than "
                     "judging by version string alone.",
        "priority": 45,
    },
    {
        "id": "cve_referenced",
        "category": "exploit",
        "pattern": r"CVE-\d{4}-\d{4,7}",
        "scanner": "searchsploit",
        "script": "searchsploit --cve {cve}",
        "title": "Look up public exploits for referenced CVEs",
        "rationale": "The output names specific CVEs; check the local ExploitDB "
                     "mirror for matching public exploits.",
        "priority": 80,
    },
    {
        "id": "software_version",
        "category": "web",
        # [^0-9]{0,24} bridges the product name to its version across BOTH shapes:
        # text ("Apache[2.2.8]", "Apache/2.2.8") and the native JSON we now prefer
        # ('"Apache":{"version":["2.2.8"]}'). Excluding digits from the bridge
        # stops it skipping over an unrelated number to reach a distant version.
        "pattern": r"\b(Apache|nginx|lighttpd|IIS|vsftpd|ProFTPD|Postfix|Samba|"
                   r"MySQL|PostgreSQL|Tomcat|Jetty|OpenSSL)\b[^0-9]{0,24}(\d+\.\d+(?:\.\d+)?)",
        "scanner": "nuclei",
        "script": "nuclei -u http://{target} -tags cve,default-login",
        "title": "Run version-targeted vulnerability templates",
        "rationale": "A specific software version was identified; nuclei's CVE "
                     "templates are the cheapest confirmation step.",
        "priority": 70,
    },
    {
        "id": "http_service",
        "category": "web",
        "pattern": r"(HTTP/1\.[01]\s+200|http_status\"?\s*[:=]\s*200|\[200 OK\])",
        "scanner": "katana",
        "script": "katana -u http://{target} -field-scope fqdn",
        "title": "Crawl the web service for additional attack surface",
        "rationale": "A live HTTP response was observed; enumerate reachable "
                     "endpoints. Scope is pinned to the target's own FQDN.",
        "priority": 55,
    },
    {
        "id": "web_directories",
        "category": "web",
        "pattern": r"(Directory\s+indexing|Index of /|/(?:admin|phpmyadmin|manager|"
                   r"wp-admin|cgi-bin)/?\b)",
        "scanner": "feroxbuster",
        "script": "feroxbuster -u http://{target} -d 2",
        "title": "Enumerate content under discovered directories",
        "rationale": "An interesting path was observed; enumerate siblings and "
                     "children rather than stopping at the one that surfaced.",
        "priority": 60,
    },
    {
        "id": "cms_detected",
        "category": "web",
        "pattern": r"\b(WordPress|Joomla|Drupal|Magento|TWiki|phpMyAdmin)\b",
        "scanner": "nuclei",
        "script": "nuclei -u http://{target} -tags cms,exposure",
        "title": "Run CMS-specific checks",
        "rationale": "A CMS was fingerprinted; CMS templates cover its known "
                     "exposures and default logins.",
        "priority": 65,
    },
    {
        "id": "credentials_found",
        "category": "credentials",
        "pattern": r"(\[\+\]\s*\S+\\\S+:\S+|password\s*[:=]\s*\S{3,}|"
                   r"valid\s+credentials|login\s+successful)",
        "scanner": "netexec",
        "script": "netexec smb {target} -u USER -p PASS --shares",
        "title": "Validate recovered credentials and map their access",
        "rationale": "Credential material appeared in the output. Confirm what "
                     "the account can actually reach — placeholders must be "
                     "filled in from the credential store before running.",
        "priority": 90,
        "needs_input": True,
    },
    {
        "id": "database_service",
        "category": "database",
        "pattern": r"\b(mysql|postgresql|mongodb|redis|mssql)\b.{0,40}\b(\d{4})\b|"
                   r"\b(3306|5432|27017|6379|1433)\b",
        "scanner": "nmap",
        "script": "nmap -sV --script '*-info,*-empty-password' {target}",
        "title": "Probe database service for unauthenticated access",
        "rationale": "A database service was referenced; check for empty or "
                     "default authentication.",
        "priority": 75,
    },
    {
        "id": "open_ports",
        "category": "recon",
        "pattern": r"(\d{1,5})/tcp\s+open|Discovered\s+open\s+port\s+(\d{1,5})",
        "scanner": "nmap",
        "script": "nmap -sV -sC -p {port} {target}",
        "title": "Service-scan newly observed open ports",
        "rationale": "Open ports were observed without full service detection; "
                     "version and default scripts refine what is actually there.",
        "priority": 60,
    },
    {
        "id": "tls_present",
        "category": "tls",
        "pattern": r"\b(TLSv1(\.[012])?|SSLv[23]|ssl-cert|Certificate)\b",
        "scanner": "tlsx",
        "script": "tlsx -u {target} -san -cn -expired -self-signed",
        "title": "Inspect TLS configuration and certificate",
        "rationale": "TLS was observed; capture protocol versions, SANs and "
                     "certificate problems.",
        "priority": 50,
    },
]

_COMPILED = [(r, re.compile(r["pattern"], re.IGNORECASE | re.MULTILINE)) for r in RULES]


def suggest_actions(content: str, tool: str = "", target: str = "",
                    port: Optional[int] = None, service: str = "",
                    llm_result: Optional[Dict[str, Any]] = None,
                    max_actions: int = 25) -> List[Dict[str, Any]]:
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

    for rule, rx in _COMPILED:
        m = rx.search(text)
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
        out.append({
            "id": rule["id"],
            "category": rule["category"],
            "title": rule["title"],
            "scanner": rule["scanner"],
            "script": script,
            "rationale": rule["rationale"],
            "priority": rule["priority"],
            "evidence": _snippet(text, m),
            "needs_input": bool(rule.get("needs_input")) or "{" in script,
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
            "source": "llm",
        })
    return out
