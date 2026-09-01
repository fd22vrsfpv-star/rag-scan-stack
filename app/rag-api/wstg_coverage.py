"""Live OWASP WSTG coverage for an engagement.

Combines two signals against the full 98-test WSTG v4.2 catalog:
  * `has_generator` — the platform can PRODUCE a test for this WSTG id
    (derived from knowledge/wstg_map.yaml's wstg_id list).
  * `evidenced`     — a finding/vuln for the engagement is EVIDENCE for it
    (classified by knowledge/wstg_coverage_map.yaml — so what ZAP/nuclei/
    whatweb/nmap/subdomain-takeover already find COUNTS, without re-testing).

A test is "covered" when it has a generator OR is evidenced; the rest are gaps,
split into automatable vs inherently-manual by the static catalog tier.
"""
import os
import re
import yaml

_MAP_PATH = os.environ.get("WSTG_MAP_PATH", "/knowledge/wstg_map.yaml")
_COV_PATH = os.environ.get("WSTG_COVERAGE_MAP_PATH", "/knowledge/wstg_coverage_map.yaml")

# Full OWASP WSTG v4.2 catalog: id -> (name, tier) where tier classifies the
# realistic automation ceiling — 'auto' (a scanner/probe can decide it) or
# 'manual' (business logic / authenticated-context judgement).
CATALOG = {
    "WSTG-INFO-01": ("Search Engine Discovery", "auto"),
    "WSTG-INFO-02": ("Fingerprint Web Server", "auto"),
    "WSTG-INFO-03": ("Review Webserver Metafiles", "auto"),
    "WSTG-INFO-04": ("Enumerate Applications", "auto"),
    "WSTG-INFO-05": ("Webpage Content Leakage", "auto"),
    "WSTG-INFO-06": ("Identify Entry Points", "auto"),
    "WSTG-INFO-07": ("Map Execution Paths", "manual"),
    "WSTG-INFO-08": ("Fingerprint Frameworks", "auto"),
    "WSTG-INFO-09": ("Fingerprint Web App", "auto"),
    "WSTG-INFO-10": ("Map Application Architecture", "manual"),
    "WSTG-CONF-01": ("Network/Infra Configuration", "auto"),
    "WSTG-CONF-02": ("App Platform Configuration", "auto"),
    "WSTG-CONF-03": ("File Extensions Handling", "auto"),
    "WSTG-CONF-04": ("Backup & Unreferenced Files", "auto"),
    "WSTG-CONF-05": ("Enumerate Admin Interfaces", "auto"),
    "WSTG-CONF-06": ("HTTP Methods", "auto"),
    "WSTG-CONF-07": ("HSTS", "auto"),
    "WSTG-CONF-08": ("RIA Cross Domain Policy", "auto"),
    "WSTG-CONF-09": ("File Permission", "manual"),
    "WSTG-CONF-10": ("Subdomain Takeover", "auto"),
    "WSTG-CONF-11": ("Cloud Storage", "auto"),
    "WSTG-IDNT-01": ("Role Definitions", "manual"),
    "WSTG-IDNT-02": ("User Registration Process", "manual"),
    "WSTG-IDNT-03": ("Account Provisioning", "manual"),
    "WSTG-IDNT-04": ("Account Enumeration", "auto"),
    "WSTG-IDNT-05": ("Weak Username Policy", "manual"),
    "WSTG-ATHN-01": ("Creds over Encrypted Channel", "auto"),
    "WSTG-ATHN-02": ("Default Credentials", "auto"),
    "WSTG-ATHN-03": ("Lockout Mechanism", "auto"),
    "WSTG-ATHN-04": ("Bypass Auth Schema", "manual"),
    "WSTG-ATHN-05": ("Remember Password", "auto"),
    "WSTG-ATHN-06": ("Browser Cache Weakness", "auto"),
    "WSTG-ATHN-07": ("Weak Password Policy", "auto"),
    "WSTG-ATHN-08": ("Weak Security Question", "manual"),
    "WSTG-ATHN-09": ("Weak Password Change", "manual"),
    "WSTG-ATHN-10": ("Weaker Auth in Alt Channel", "manual"),
    "WSTG-ATHZ-01": ("Directory Traversal / File Include", "auto"),
    "WSTG-ATHZ-02": ("Bypass Authorization Schema", "manual"),
    "WSTG-ATHZ-03": ("Privilege Escalation", "manual"),
    "WSTG-ATHZ-04": ("IDOR", "auto"),
    "WSTG-ATHZ-05": ("OAuth Weaknesses", "manual"),
    "WSTG-SESS-01": ("Session Management Schema", "manual"),
    "WSTG-SESS-02": ("Cookie Attributes", "auto"),
    "WSTG-SESS-03": ("Session Fixation", "auto"),
    "WSTG-SESS-04": ("Exposed Session Variables", "auto"),
    "WSTG-SESS-05": ("CSRF", "auto"),
    "WSTG-SESS-06": ("Logout Functionality", "auto"),
    "WSTG-SESS-07": ("Session Timeout", "auto"),
    "WSTG-SESS-08": ("Session Puzzling", "manual"),
    "WSTG-SESS-09": ("Session Hijacking", "auto"),
    "WSTG-INPV-01": ("Reflected XSS", "auto"),
    "WSTG-INPV-02": ("Stored XSS", "auto"),
    "WSTG-INPV-03": ("HTTP Verb Tampering", "auto"),
    "WSTG-INPV-04": ("HTTP Parameter Pollution", "auto"),
    "WSTG-INPV-05": ("SQL Injection", "auto"),
    "WSTG-INPV-06": ("LDAP Injection", "auto"),
    "WSTG-INPV-07": ("XML/XXE Injection", "auto"),
    "WSTG-INPV-08": ("SSI Injection", "auto"),
    "WSTG-INPV-09": ("XPath Injection", "auto"),
    "WSTG-INPV-10": ("IMAP/SMTP Injection", "auto"),
    "WSTG-INPV-11": ("Code Injection", "auto"),
    "WSTG-INPV-12": ("Command Injection", "auto"),
    "WSTG-INPV-13": ("Format String", "auto"),
    "WSTG-INPV-14": ("Incubated Vulnerability", "manual"),
    "WSTG-INPV-15": ("HTTP Splitting/Smuggling", "auto"),
    "WSTG-INPV-16": ("HTTP Incoming Requests", "manual"),
    "WSTG-INPV-17": ("Host Header Injection", "auto"),
    "WSTG-INPV-18": ("SSTI", "auto"),
    "WSTG-INPV-19": ("SSRF", "auto"),
    "WSTG-ERRH-01": ("Improper Error Handling", "auto"),
    "WSTG-ERRH-02": ("Stack Traces", "auto"),
    "WSTG-CRYP-01": ("Weak TLS", "auto"),
    "WSTG-CRYP-02": ("Padding Oracle", "auto"),
    "WSTG-CRYP-03": ("Sensitive Info Unencrypted", "auto"),
    "WSTG-CRYP-04": ("Weak Encryption", "auto"),
    "WSTG-BUSL-01": ("Business Logic Data Validation", "manual"),
    "WSTG-BUSL-02": ("Ability to Forge Requests", "manual"),
    "WSTG-BUSL-03": ("Integrity Checks", "manual"),
    "WSTG-BUSL-04": ("Process Timing", "manual"),
    "WSTG-BUSL-05": ("Function Usage Limits", "manual"),
    "WSTG-BUSL-06": ("Workflow Circumvention", "manual"),
    "WSTG-BUSL-07": ("Defenses Against Misuse", "manual"),
    "WSTG-BUSL-08": ("Upload of Unexpected File Types", "auto"),
    "WSTG-BUSL-09": ("Upload of Malicious Files", "auto"),
    "WSTG-CLNT-01": ("DOM-Based XSS", "auto"),
    "WSTG-CLNT-02": ("JavaScript Execution", "auto"),
    "WSTG-CLNT-03": ("HTML Injection", "auto"),
    "WSTG-CLNT-04": ("Client-side URL Redirect", "auto"),
    "WSTG-CLNT-05": ("CSS Injection", "auto"),
    "WSTG-CLNT-06": ("Client Resource Manipulation", "auto"),
    "WSTG-CLNT-07": ("CORS", "auto"),
    "WSTG-CLNT-08": ("Cross-Site Flashing", "auto"),
    "WSTG-CLNT-09": ("Clickjacking", "auto"),
    "WSTG-CLNT-10": ("WebSockets", "auto"),
    "WSTG-CLNT-11": ("Web Messaging", "auto"),
    "WSTG-CLNT-12": ("Browser Storage", "auto"),
    "WSTG-CLNT-13": ("Cross-Site Script Inclusion", "auto"),
    "WSTG-APIT-01": ("API / GraphQL Testing", "auto"),
}
_ID_RE = re.compile(r"WSTG-[A-Z]+-\d+")


def _load_yaml(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def generator_wstg_ids():
    """WSTG ids the platform can PRODUCE a test for (from the map's wstg_id list)."""
    ids = set()
    for e in (_load_yaml(_MAP_PATH).get("entries") or []):
        w = e.get("wstg_id")
        for x in (w if isinstance(w, list) else [w]):
            ids.update(_ID_RE.findall(str(x)))
    ids.add("WSTG-APIT-01")   # graphql_introspection uses the APIT-99 alias
    return ids


def coverage_rules():
    return _load_yaml(_COV_PATH).get("rules") or []


def evidenced_ids(findings):
    """WSTG ids EVIDENCED by the engagement's findings (source/name/tag rules)."""
    rules = coverage_rules()
    ids = set()
    for f in findings:
        src = (f.get("source") or "").lower()
        text = ((f.get("name") or "") + " " + (f.get("issue_type") or "")).lower()
        tags = {str(t).lower() for t in (f.get("tags") or [])}
        for r in rules:
            wid = r.get("wstg_id")
            if r.get("sources") and src in {s.lower() for s in r["sources"]}:
                ids.add(wid)
            elif r.get("name_contains") and any(s.lower() in text for s in r["name_contains"]):
                ids.add(wid)
            elif r.get("nuclei_tags") and tags & {t.lower() for t in r["nuclei_tags"]}:
                ids.add(wid)
    return ids


def compute(findings):
    """Return the full 98-test coverage matrix + summary for these findings."""
    gen = generator_wstg_ids()
    ev = evidenced_ids(findings)
    rows, by_cat = [], {}
    for cid, (name, tier) in CATALOG.items():
        fam = cid.split("-")[1]
        has_gen, evidenced = cid in gen, cid in ev
        covered = has_gen or evidenced
        rows.append({"id": cid, "name": name, "category": fam, "auto_tier": tier,
                     "has_generator": has_gen, "evidenced": evidenced,
                     "covered": covered})
        c = by_cat.setdefault(fam, {"total": 0, "covered": 0})
        c["total"] += 1
        c["covered"] += 1 if covered else 0
    total = len(rows)
    covered = sum(1 for r in rows if r["covered"])
    gaps_auto = [r["id"] for r in rows if not r["covered"] and r["auto_tier"] == "auto"]
    gaps_manual = [r["id"] for r in rows if not r["covered"] and r["auto_tier"] == "manual"]
    return {
        "summary": {
            "total": total, "covered": covered, "uncovered": total - covered,
            "pct_covered": round(100 * covered / total, 1) if total else 0.0,
            "with_generator": sum(1 for r in rows if r["has_generator"]),
            "evidenced": sum(1 for r in rows if r["evidenced"]),
            "gaps_automatable": len(gaps_auto), "gaps_manual": len(gaps_manual),
        },
        "by_category": by_cat,
        "gaps_automatable": gaps_auto,
        "gaps_manual": gaps_manual,
        "tests": rows,
    }
