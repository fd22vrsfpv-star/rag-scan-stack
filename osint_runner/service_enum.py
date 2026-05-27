"""
Service-Specific Enumeration Module.

Performs targeted enumeration for:
- Email infrastructure (SPF, DKIM, DMARC, MX banners, provider detection)
- DNS infrastructure (zone transfer, reverse DNS, nameserver fingerprinting)
- SMTP enumeration (banner, TLS, auth methods, open relay)
"""

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.reversename
import socket
import ssl
import json
import logging
import ipaddress
import re
import smtplib
from typing import Optional
from datetime import datetime

log = logging.getLogger("service-enum")

# Use public DNS resolvers (Docker's internal DNS can't resolve external domains)
_resolver = dns.resolver.Resolver()
_resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
_resolver.timeout = 10
_resolver.lifetime = 15


# ── Email Infrastructure ─────────────────────────────

def check_spf(domain: str) -> dict:
    """Parse SPF record from DNS TXT."""
    result = {"domain": domain, "record_type": "SPF", "exists": False}
    try:
        answers = _resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                result["exists"] = True
                result["record"] = txt
                result["mechanisms"] = []
                result["includes"] = []
                result["all_policy"] = "missing"
                for part in txt.split():
                    if part.startswith("include:"):
                        result["includes"].append(part.split(":", 1)[1])
                    elif part.startswith("ip4:") or part.startswith("ip6:"):
                        result["mechanisms"].append(part)
                    elif part in ("+all", "-all", "~all", "?all"):
                        result["all_policy"] = part
                # Detect provider from includes
                result["providers"] = _detect_email_providers(result["includes"])
                # Security assessment
                if result["all_policy"] == "-all":
                    result["assessment"] = "strict"
                elif result["all_policy"] == "~all":
                    result["assessment"] = "softfail"
                elif result["all_policy"] in ("+all", "?all"):
                    result["assessment"] = "permissive"
                else:
                    result["assessment"] = "missing_all"
                break
    except dns.resolver.NXDOMAIN:
        result["error"] = "domain not found"
    except dns.resolver.NoAnswer:
        result["error"] = "no TXT records"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_dmarc(domain: str) -> dict:
    """Parse DMARC record from _dmarc.domain."""
    result = {"domain": domain, "record_type": "DMARC", "exists": False}
    try:
        answers = _resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                result["exists"] = True
                result["record"] = txt
                result["tags"] = {}
                for part in txt.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        result["tags"][k.strip()] = v.strip()
                result["policy"] = result["tags"].get("p", "none")
                result["subdomain_policy"] = result["tags"].get("sp", result["policy"])
                result["pct"] = result["tags"].get("pct", "100")
                result["rua"] = result["tags"].get("rua", "")
                result["ruf"] = result["tags"].get("ruf", "")
                # Security assessment
                if result["policy"] == "reject":
                    result["assessment"] = "strict"
                elif result["policy"] == "quarantine":
                    result["assessment"] = "moderate"
                else:
                    result["assessment"] = "permissive"
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        result["error"] = "no DMARC record"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_dkim(domain: str, selectors: list[str] = None) -> dict:
    """Check DKIM records for common selectors."""
    if selectors is None:
        selectors = [
            "default", "google", "selector1", "selector2",  # O365
            "k1", "k2", "k3",  # Mailchimp
            "dkim", "mail", "smtp", "s1", "s2",
            "mandrill", "everlytickey1", "everlytickey2",
            "cm", "protonmail", "protonmail2", "protonmail3",
        ]
    result = {"domain": domain, "record_type": "DKIM", "exists": False, "selectors_found": []}
    for sel in selectors:
        try:
            answers = _resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    result["exists"] = True
                    entry = {"selector": sel, "record": txt[:200]}
                    # Extract key type
                    for part in txt.split(";"):
                        part = part.strip()
                        if part.startswith("k="):
                            entry["key_type"] = part.split("=", 1)[1]
                    result["selectors_found"].append(entry)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue
    return result


def enumerate_mx(domain: str) -> dict:
    """Enumerate MX records and probe SMTP banners."""
    result = {"domain": domain, "record_type": "MX", "servers": []}
    try:
        answers = _resolver.resolve(domain, "MX")
        for rdata in sorted(answers, key=lambda r: r.preference):
            mx_host = str(rdata.exchange).rstrip(".")
            server = {
                "priority": rdata.preference,
                "host": mx_host,
                "banner": None,
                "tls": None,
                "provider": None,
            }
            # SMTP banner grab
            try:
                with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
                    banner = smtp.docmd("NOOP")[1].decode(errors="replace") if hasattr(smtp, 'docmd') else ""
                    server["banner"] = smtp.ehlo_resp.decode(errors="replace") if smtp.ehlo_resp else banner
                    # Check STARTTLS
                    try:
                        smtp.starttls()
                        server["tls"] = True
                    except Exception:
                        server["tls"] = False
            except Exception as e:
                server["banner"] = f"connection failed: {str(e)[:100]}"
            # Detect provider
            server["provider"] = _detect_mx_provider(mx_host)
            result["servers"].append(server)
    except dns.resolver.NXDOMAIN:
        result["error"] = "domain not found"
    except dns.resolver.NoAnswer:
        result["error"] = "no MX records"
    except Exception as e:
        result["error"] = str(e)
    return result


def _detect_email_providers(includes: list[str]) -> list[str]:
    """Detect email service providers from SPF includes."""
    providers = []
    patterns = {
        "google": "Google Workspace",
        "googlemail": "Google Workspace",
        "_spf.google": "Google Workspace",
        "outlook": "Microsoft 365",
        "protection.outlook": "Microsoft 365",
        "spf.protection": "Microsoft 365",
        "amazonses": "Amazon SES",
        "sendgrid": "SendGrid",
        "mailchimp": "Mailchimp",
        "mandrill": "Mandrill",
        "zendesk": "Zendesk",
        "freshdesk": "Freshdesk",
        "salesforce": "Salesforce",
        "hubspot": "HubSpot",
        "mimecast": "Mimecast",
        "proofpoint": "Proofpoint",
        "barracuda": "Barracuda",
        "pphosted": "Proofpoint",
        "mailgun": "Mailgun",
        "postmark": "Postmark",
    }
    for inc in includes:
        inc_lower = inc.lower()
        for pattern, provider in patterns.items():
            if pattern in inc_lower and provider not in providers:
                providers.append(provider)
    return providers


def _detect_mx_provider(mx_host: str) -> str | None:
    """Detect email provider from MX hostname."""
    mx_lower = mx_host.lower()
    if "google" in mx_lower or "gmail" in mx_lower:
        return "Google Workspace"
    if "outlook" in mx_lower or "microsoft" in mx_lower:
        return "Microsoft 365"
    if "pphosted" in mx_lower or "proofpoint" in mx_lower:
        return "Proofpoint"
    if "mimecast" in mx_lower:
        return "Mimecast"
    if "barracuda" in mx_lower:
        return "Barracuda"
    if "messagelabs" in mx_lower or "symantec" in mx_lower:
        return "Symantec/Broadcom"
    if "amazonses" in mx_lower or "inbound-smtp" in mx_lower:
        return "Amazon SES"
    if "mailgun" in mx_lower:
        return "Mailgun"
    if "sendgrid" in mx_lower:
        return "SendGrid"
    return None


# ── DNS Infrastructure ────────────────────────────────

def enumerate_dns_records(domain: str) -> dict:
    """Comprehensive DNS record enumeration."""
    result = {"domain": domain, "records": {}}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]
    for rtype in record_types:
        try:
            answers = _resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                records.append(rdata.to_text())
            if records:
                result["records"][rtype] = records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except Exception:
            continue
    return result


def attempt_zone_transfer(domain: str) -> dict:
    """Attempt AXFR zone transfer on all nameservers."""
    result = {"domain": domain, "vulnerable": False, "nameservers": [], "records_transferred": 0}
    try:
        ns_answers = _resolver.resolve(domain, "NS")
        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata).rstrip(".")
            ns_entry = {"nameserver": ns_host, "axfr_allowed": False, "records": []}
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
                ns_entry["axfr_allowed"] = True
                result["vulnerable"] = True
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            ns_entry["records"].append({
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "value": rdata.to_text(),
                            })
                result["records_transferred"] += len(ns_entry["records"])
            except Exception as e:
                ns_entry["error"] = str(e)[:100]
            result["nameservers"].append(ns_entry)
    except Exception as e:
        result["error"] = str(e)
    return result


def reverse_dns_sweep(cidr: str, limit: int = 256) -> dict:
    """Reverse DNS (PTR) lookup on an IP range."""
    result = {"cidr": cidr, "records": [], "total_ips": 0, "resolved": 0}
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())[:limit]
        result["total_ips"] = len(hosts)
        for ip in hosts:
            try:
                rev_name = dns.reversename.from_address(str(ip))
                answers = _resolver.resolve(rev_name, "PTR")
                for rdata in answers:
                    result["records"].append({
                        "ip": str(ip),
                        "ptr": str(rdata).rstrip("."),
                    })
                    result["resolved"] += 1
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except Exception:
                continue
    except Exception as e:
        result["error"] = str(e)
    return result


def fingerprint_nameservers(domain: str) -> dict:
    """Identify DNS server software via version queries and response analysis."""
    result = {"domain": domain, "nameservers": []}
    try:
        ns_answers = _resolver.resolve(domain, "NS")
        for ns_rdata in ns_answers:
            ns_host = str(ns_rdata).rstrip(".")
            ns_info = {"host": ns_host, "ip": None, "software": None, "version_bind": None}
            # Resolve NS IP
            try:
                a_answers = _resolver.resolve(ns_host, "A")
                ns_info["ip"] = str(a_answers[0])
            except Exception:
                pass
            # Try version.bind CHAOS query
            try:
                query = dns.message.make_query("version.bind", "TXT", "CH")
                if ns_info["ip"]:
                    response = dns.query.udp(query, ns_info["ip"], timeout=5)
                    for rrset in response.answer:
                        for rdata in rrset:
                            ns_info["version_bind"] = rdata.to_text().strip('"')
            except Exception:
                pass
            # Detect from hostname patterns
            ns_lower = ns_host.lower()
            if "cloudflare" in ns_lower:
                ns_info["software"] = "Cloudflare DNS"
            elif "awsdns" in ns_lower:
                ns_info["software"] = "AWS Route 53"
            elif "azure-dns" in ns_lower or "microsoft" in ns_lower:
                ns_info["software"] = "Azure DNS"
            elif "google" in ns_lower or "googledomains" in ns_lower:
                ns_info["software"] = "Google Cloud DNS"
            elif "domaincontrol" in ns_lower:
                ns_info["software"] = "GoDaddy DNS"
            elif "nsone" in ns_lower or "ns1" in ns_lower:
                ns_info["software"] = "NS1"
            elif ns_info.get("version_bind"):
                ns_info["software"] = ns_info["version_bind"]
            result["nameservers"].append(ns_info)
    except Exception as e:
        result["error"] = str(e)
    return result


# ── Full Enumeration Runner ───────────────────────────

def run_full_email_enum(domain: str) -> dict:
    """Run complete email infrastructure enumeration."""
    log.info(f"Starting email enumeration for {domain}")
    results = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "spf": check_spf(domain),
        "dmarc": check_dmarc(domain),
        "dkim": check_dkim(domain),
        "mx": enumerate_mx(domain),
    }
    # Overall email security score
    score = 0
    if results["spf"]["exists"]:
        score += 1
        if results["spf"].get("assessment") == "strict":
            score += 1
    if results["dmarc"]["exists"]:
        score += 1
        if results["dmarc"].get("assessment") == "strict":
            score += 1
    if results["dkim"]["exists"]:
        score += 1
    results["email_security_score"] = f"{score}/5"
    results["providers"] = list(set(
        results["spf"].get("providers", []) +
        [s["provider"] for s in results["mx"].get("servers", []) if s.get("provider")]
    ))
    return results


def run_full_dns_enum(domain: str, reverse_cidr: str = None) -> dict:
    """Run complete DNS infrastructure enumeration."""
    log.info(f"Starting DNS enumeration for {domain}")
    results = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "records": enumerate_dns_records(domain),
        "zone_transfer": attempt_zone_transfer(domain),
        "nameservers": fingerprint_nameservers(domain),
    }
    if reverse_cidr:
        results["reverse_dns"] = reverse_dns_sweep(reverse_cidr)
    return results
