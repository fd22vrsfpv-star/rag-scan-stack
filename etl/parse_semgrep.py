"""
Parse Semgrep JSON output into sast_findings.

Supports three input modes:
  1. Pre-run Semgrep JSON (operator ran semgrep locally, uploads results)
  2. GitHub URL (platform clones + scans)
  3. Web-source (platform fetches page source + scans inline JS/HTML)

All three produce the same normalized sast_findings rows that feed
into the gather pipeline for exploit-workbench builds.
"""
import hashlib
import json
import logging
import os
import re
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("parse_semgrep")


def sast_fingerprint(rule_id: str, file_path: str, line_start: int,
                     matched_code: str) -> str:
    """Stable dedup hash for a SAST finding."""
    raw = f"{rule_id}|{file_path}|{line_start}|{matched_code}"
    return hashlib.sha256(raw.encode()).hexdigest()[:40]


def parse_semgrep_json(raw: str | dict | list) -> List[Dict[str, Any]]:
    """Parse Semgrep JSON output into normalized finding dicts.

    Accepts the full Semgrep JSON output (with `results` key) or a bare
    list of result objects.

    Returns a list of dicts ready for INSERT into sast_findings.
    """
    if isinstance(raw, str):
        data = json.loads(raw)
    else:
        data = raw

    if isinstance(data, dict):
        results = data.get("results") or []
        version = data.get("version", "")
    elif isinstance(data, list):
        results = data
        version = ""
    else:
        return []

    findings: List[Dict[str, Any]] = []
    for r in results:
        extra = r.get("extra") or {}
        metadata = extra.get("metadata") or {}

        rule_id = r.get("check_id") or r.get("rule_id") or ""
        file_path = r.get("path") or ""
        start = r.get("start") or {}
        end = r.get("end") or {}
        line_start = start.get("line") or start.get("offset", 0)
        line_end = end.get("line") or end.get("offset", 0)
        col_start = start.get("col", 0)
        col_end = end.get("col", 0)

        matched_code = extra.get("lines") or ""
        if isinstance(matched_code, list):
            matched_code = "\n".join(matched_code)
        matched_code = str(matched_code).strip()

        severity = (extra.get("severity") or metadata.get("severity") or "INFO").upper()
        sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "info"}
        normalized_severity = sev_map.get(severity, "info")

        confidence = (metadata.get("confidence") or "MEDIUM").upper()
        message = extra.get("message") or ""
        fix = extra.get("fix") or None

        cwe_raw = metadata.get("cwe") or []
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        cwes = [str(c) for c in cwe_raw]

        owasp_raw = metadata.get("owasp") or []
        if isinstance(owasp_raw, str):
            owasp_raw = [owasp_raw]

        vuln_class = _classify_vuln(rule_id, cwes, message)

        fp = sast_fingerprint(rule_id, file_path, line_start, matched_code)

        findings.append({
            "rule_id": rule_id,
            "severity": normalized_severity,
            "confidence": confidence,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "col_start": col_start,
            "col_end": col_end,
            "matched_code": matched_code[:4000],
            "message": message[:2000],
            "fix": (fix or "")[:2000] if fix else None,
            "cwe": cwes,
            "owasp": [str(o) for o in owasp_raw],
            "vuln_class": vuln_class,
            "metadata": metadata,
            "fingerprint": fp,
            "semgrep_version": version,
        })

    return findings


# Vuln-class mapping: what the build-PoC pipeline uses to focus attacks
_CWE_VULN_MAP = {
    "CWE-89": "sqli", "CWE-564": "sqli",
    "CWE-79": "xss", "CWE-80": "xss",
    "CWE-78": "cmdi", "CWE-77": "cmdi", "CWE-94": "cmdi",
    "CWE-22": "lfi", "CWE-23": "lfi", "CWE-36": "lfi", "CWE-73": "lfi",
    "CWE-434": "upload",
    "CWE-918": "ssrf",
    "CWE-611": "xxe",
    "CWE-502": "deserialization",
    "CWE-287": "auth-bypass", "CWE-306": "auth-bypass",
    "CWE-862": "idor", "CWE-639": "idor",
    "CWE-1321": "prototype-pollution",
    "CWE-90": "ldap-injection",
    "CWE-943": "nosql-injection",
    "CWE-352": "csrf",
    "CWE-798": "hardcoded-secret",
    "CWE-259": "hardcoded-secret",
    "CWE-321": "hardcoded-secret",
}

_RULE_VULN_MAP = {
    "sqli": "sqli", "sql-injection": "sqli", "sql_injection": "sqli",
    "xss": "xss", "cross-site-scripting": "xss",
    "command-injection": "cmdi", "os-command": "cmdi", "exec-detected": "cmdi",
    "path-traversal": "lfi", "directory-traversal": "lfi",
    "file-upload": "upload", "unrestricted-upload": "upload",
    "ssrf": "ssrf", "server-side-request": "ssrf",
    "xxe": "xxe", "xml-external": "xxe",
    "deserialization": "deserialization", "pickle": "deserialization",
    "auth-bypass": "auth-bypass", "broken-auth": "auth-bypass",
    "idor": "idor", "insecure-direct": "idor",
    "csrf": "csrf",
    "ssti": "ssti", "template-injection": "ssti",
    "ldap": "ldap-injection",
    "nosql": "nosql-injection",
    "prototype-pollut": "prototype-pollution",
    "hardcoded-secret": "hardcoded-secret", "hardcoded-password": "hardcoded-secret",
    "hardcoded-key": "hardcoded-secret",
}


def _classify_vuln(rule_id: str, cwes: list, message: str) -> str:
    """Map a Semgrep finding to the exploit pipeline's vuln_class taxonomy."""
    for cwe in cwes:
        m = re.search(r'CWE-(\d+)', str(cwe))
        if m:
            full_cwe = f"CWE-{m.group(1)}"
            if full_cwe in _CWE_VULN_MAP:
                return _CWE_VULN_MAP[full_cwe]

    rule_lower = rule_id.lower()
    for pattern, cls in _RULE_VULN_MAP.items():
        if pattern in rule_lower:
            return cls

    msg_lower = (message or "").lower()
    for pattern, cls in _RULE_VULN_MAP.items():
        if pattern in msg_lower:
            return cls

    return "other"


def findings_to_attack_surface(findings: List[Dict]) -> Dict[str, Any]:
    """Summarize SAST findings into an attack-surface dict the gather
    pipeline can consume directly. Groups by vuln_class and extracts
    actionable info (file paths, code patterns, injection points).

    This is what makes SAST findings *focus* the network attack:
    the build-PoC gather phase uses these to know exactly which
    parameter, endpoint pattern, or code path to target."""
    by_class: Dict[str, list] = {}
    for f in findings:
        vc = f.get("vuln_class", "other")
        by_class.setdefault(vc, []).append(f)

    surface: Dict[str, Any] = {
        "vuln_classes": list(by_class.keys()),
        "total_findings": len(findings),
        "by_severity": {},
        "injection_points": [],
        "hardcoded_secrets": [],
        "attack_vectors": [],
    }

    for f in findings:
        sev = f.get("severity", "info")
        surface["by_severity"][sev] = surface["by_severity"].get(sev, 0) + 1

    for vc, items in by_class.items():
        if vc == "hardcoded-secret":
            for f in items[:10]:
                surface["hardcoded_secrets"].append({
                    "file": f["file_path"],
                    "line": f["line_start"],
                    "rule": f["rule_id"],
                    "hint": f["message"][:200],
                })
            continue

        for f in items:
            endpoint_hint = _extract_endpoint_hint(f)
            param_hint = _extract_param_hint(f)
            surface["injection_points"].append({
                "vuln_class": vc,
                "file": f["file_path"],
                "line": f["line_start"],
                "code": f["matched_code"][:300],
                "rule": f["rule_id"],
                "severity": f["severity"],
                "endpoint_hint": endpoint_hint,
                "param_hint": param_hint,
            })

        surface["attack_vectors"].append({
            "vuln_class": vc,
            "count": len(items),
            "files": list({f["file_path"] for f in items})[:10],
            "top_rule": items[0]["rule_id"],
        })

    surface["injection_points"].sort(
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity", "info"), 5)
    )

    return surface


def _extract_endpoint_hint(f: Dict) -> Optional[str]:
    """Try to extract a URL/route pattern from the file path or code."""
    file_path = f.get("file_path", "")
    code = f.get("matched_code", "")

    route_patterns = [
        r"""@(?:app|router|api)\.\w+\(['"](/[^'"]+)['"]""",
        r"""path\(['"](/[^'"]+)['"]""",
        r"""url\(['"](/[^'"]+)['"]""",
        r"""Route\(['"](/[^'"]+)['"]""",
        r"""\.(?:get|post|put|delete|patch)\(['"](/[^'"]+)['"]""",
    ]
    for pat in route_patterns:
        m = re.search(pat, code)
        if m:
            return m.group(1)

    if "/views/" in file_path or "/controllers/" in file_path or "/routes/" in file_path:
        parts = file_path.split("/")
        return "/" + "/".join(parts[-2:]).replace(".py", "").replace(".js", "").replace(".php", "")

    return None


def _extract_param_hint(f: Dict) -> Optional[str]:
    """Try to extract the vulnerable parameter name from the code."""
    code = f.get("matched_code", "")
    patterns = [
        r"""request\.(?:GET|POST|args|form|params|query)\.get\(\s*['"]([\w-]+)['"]""",
        r"""request\.(?:GET|POST|args|form|params|query)\[?['"]([\w-]+)['"]""",
        r"""params\[?['"]([\w-]+)['"]""",
        r"""\$_(?:GET|POST|REQUEST)\[['"]([\w-]+)['"]""",
        r"""req\.(?:body|query|params)\.([\w-]+)""",
        r"""getParameter\(['"]([\w-]+)['"]""",
    ]
    for pat in patterns:
        m = re.search(pat, code)
        if m:
            return m.group(1)
    return None
