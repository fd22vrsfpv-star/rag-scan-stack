"""
Finding fingerprinting for cross-tool deduplication and delta comparison.

A fingerprint is a stable MD5 hash that identifies a unique finding regardless
of which tool discovered it. Two findings from different tools that describe
the same vulnerability on the same target should produce the same fingerprint.

Fingerprint strategies:
  - vulns: normalize by CVE (if present) + asset + port, else by script_base + asset + port
  - web_findings: normalize by url + issue_type + name
  - recon_findings: normalize by source + finding_type + target + data_key
"""
import hashlib
import re
from typing import Optional, List


def _md5(text: str) -> str:
    """Compute MD5 hex digest of a string."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _normalize_script(script: str) -> str:
    """
    Extract base tool identifier from script field.
    Examples:
      'nmap:smb-vuln-ms17-010' → 'smb-vuln-ms17-010'
      'nessus:97833' → 'nessus:97833'
      'nuclei:CVE-2021-44228' → 'nuclei:CVE-2021-44228'
    """
    if not script:
        return ""
    return script.strip().lower()


def _extract_first_cve(cves: Optional[List[str]]) -> Optional[str]:
    """Get first CVE from list, normalized."""
    if not cves:
        return None
    for cve in cves:
        if cve and re.match(r"CVE-\d{4}-\d+", cve, re.IGNORECASE):
            return cve.upper()
    return None


def vuln_fingerprint(
    ip: Optional[str],
    port: Optional[int],
    script: Optional[str],
    cves: Optional[List[str]] = None,
    output: Optional[str] = None,
) -> str:
    """
    Generate fingerprint for a vulnerability finding.

    Strategy:
    1. If CVE exists: hash(cve | ip | port) — groups same CVE across tools
    2. Else: hash(script_normalized | ip | port) — tool-specific identity
    """
    ip_str = (ip or "").strip()
    port_str = str(port) if port else "0"

    first_cve = _extract_first_cve(cves)
    if first_cve:
        # CVE-based: same CVE on same host:port = same finding
        key = f"cve|{first_cve}|{ip_str}|{port_str}"
    else:
        # Script-based: tool-specific identity
        script_norm = _normalize_script(script)
        key = f"script|{script_norm}|{ip_str}|{port_str}"

    return _md5(key)


def web_fingerprint(
    url: Optional[str],
    source: Optional[str],
    name: Optional[str],
    issue_type: Optional[str] = None,
) -> str:
    """
    Generate fingerprint for a web finding.

    Strategy: hash(url_normalized | name | issue_type)
    Source is excluded so the same finding from ZAP and Nuclei deduplicates.
    """
    url_str = (url or "").strip().lower().rstrip("/")
    name_str = (name or "").strip().lower()
    issue_str = (issue_type or "").strip().lower()

    key = f"web|{url_str}|{name_str}|{issue_str}"
    return _md5(key)


def recon_fingerprint(
    source: Optional[str],
    finding_type: Optional[str],
    target: Optional[str],
    data_key: Optional[str] = None,
) -> str:
    """
    Generate fingerprint for a recon finding.

    Strategy: hash(source | finding_type | target | data_key)
    Recon findings are source-specific (subfinder subdomain != crtsh cert).
    data_key provides additional discrimination (e.g., subdomain value, cert hash).
    """
    source_str = (source or "").strip().lower()
    type_str = (finding_type or "").strip().lower()
    target_str = (target or "").strip().lower()
    data_str = (data_key or "").strip().lower()

    key = f"recon|{source_str}|{type_str}|{target_str}|{data_str}"
    return _md5(key)
