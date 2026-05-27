#!/usr/bin/env python3
"""
Self-contained service enumeration CLI for remote node execution.
Zero external dependencies — uses dig/host as fallback if dnspython unavailable.

Usage:
    python3 service_enum_cli.py --domain example.com --output /tmp/results.json
    python3 service_enum_cli.py --domain example.com --services email --output /tmp/results.json
    python3 service_enum_cli.py --domain example.com --services dns --reverse-cidr 10.0.1.0/24
"""

import argparse
import json
import subprocess
import sys
import re
import ipaddress
import socket
from datetime import datetime

# Try dnspython, fall back to dig/host CLI
USE_DNSPYTHON = False
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    import dns.reversename
    import dns.message
    USE_DNSPYTHON = True
    _resolver = dns.resolver.Resolver()
    _resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    _resolver.timeout = 10
    _resolver.lifetime = 15
except ImportError:
    # Auto-install attempt (non-fatal)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "dnspython"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        import dns.resolver, dns.zone, dns.query, dns.rdatatype, dns.reversename, dns.message
        USE_DNSPYTHON = True
        _resolver = dns.resolver.Resolver()
        _resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        _resolver.timeout = 10
        _resolver.lifetime = 15
    except Exception:
        pass

LOG_PREFIX = "[service-enum]"


# ── CLI fallback helpers ─────────────────────────────

def _run_cmd(cmd, timeout=15):
    """Run a command and return stdout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _dig(domain, rtype, server="8.8.8.8"):
    """Query DNS via dig CLI."""
    out = _run_cmd(["dig", f"@{server}", domain, rtype, "+short", "+time=5", "+tries=2"])
    return [line.strip() for line in out.split("\n") if line.strip()]


def _dig_full(domain, rtype, server="8.8.8.8"):
    """Query DNS via dig CLI, return full answer section."""
    out = _run_cmd(["dig", f"@{server}", domain, rtype, "+noall", "+answer", "+time=5", "+tries=2"])
    return out


def _dig_txt(domain, server="8.8.8.8"):
    """Get TXT records, reassemble quoted strings."""
    lines = _dig(domain, "TXT", server)
    results = []
    for line in lines:
        # Remove outer quotes and join split TXT strings
        clean = line.replace('" "', '').strip('"')
        results.append(clean)
    return results


# ── Email enumeration ────────────────────────────────

def check_spf(domain):
    result = {"domain": domain, "record_type": "SPF", "exists": False}
    try:
        if USE_DNSPYTHON:
            answers = _resolver.resolve(domain, "TXT")
            txts = [rdata.to_text().strip('"').replace('" "', '') for rdata in answers]
        else:
            txts = _dig_txt(domain)

        for txt in txts:
            if txt.startswith("v=spf1"):
                result["exists"] = True
                result["record"] = txt
                result["includes"] = [p.split(":", 1)[1] for p in txt.split() if p.startswith("include:")]
                result["mechanisms"] = [p for p in txt.split() if p.startswith(("ip4:", "ip6:"))]
                result["all_policy"] = "missing"
                for p in txt.split():
                    if p in ("+all", "-all", "~all", "?all"):
                        result["all_policy"] = p
                result["providers"] = _detect_providers(result["includes"])
                if result["all_policy"] == "-all": result["assessment"] = "strict"
                elif result["all_policy"] == "~all": result["assessment"] = "softfail"
                elif result["all_policy"] in ("+all", "?all"): result["assessment"] = "permissive"
                else: result["assessment"] = "missing_all"
                break
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def check_dmarc(domain):
    result = {"domain": domain, "record_type": "DMARC", "exists": False}
    try:
        if USE_DNSPYTHON:
            answers = _resolver.resolve(f"_dmarc.{domain}", "TXT")
            txts = [rdata.to_text().strip('"').replace('" "', '') for rdata in answers]
        else:
            txts = _dig_txt(f"_dmarc.{domain}")

        for txt in txts:
            if txt.startswith("v=DMARC1"):
                result["exists"] = True
                result["record"] = txt
                tags = {}
                for part in txt.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        tags[k.strip()] = v.strip()
                result["tags"] = tags
                result["policy"] = tags.get("p", "none")
                result["subdomain_policy"] = tags.get("sp", result["policy"])
                result["rua"] = tags.get("rua", "")
                result["ruf"] = tags.get("ruf", "")
                if result["policy"] == "reject": result["assessment"] = "strict"
                elif result["policy"] == "quarantine": result["assessment"] = "moderate"
                else: result["assessment"] = "permissive"
                break
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def check_dkim(domain, selectors=None):
    if not selectors:
        selectors = ["default", "google", "selector1", "selector2", "k1", "k2", "k3",
                     "dkim", "mail", "s1", "s2", "mandrill", "cm", "protonmail"]
    result = {"domain": domain, "record_type": "DKIM", "exists": False, "selectors_found": []}
    for sel in selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        try:
            if USE_DNSPYTHON:
                answers = _resolver.resolve(dkim_domain, "TXT")
                txts = [rdata.to_text().strip('"').replace('" "', '') for rdata in answers]
            else:
                txts = _dig_txt(dkim_domain)

            for txt in txts:
                if "p=" in txt:
                    result["exists"] = True
                    entry = {"selector": sel, "record": txt[:200]}
                    for part in txt.split(";"):
                        part = part.strip()
                        if part.startswith("k="):
                            entry["key_type"] = part.split("=", 1)[1]
                    result["selectors_found"].append(entry)
        except Exception:
            continue
    return result


def enumerate_mx(domain):
    result = {"domain": domain, "record_type": "MX", "servers": []}
    try:
        if USE_DNSPYTHON:
            answers = _resolver.resolve(domain, "MX")
            mx_list = [(rdata.preference, str(rdata.exchange).rstrip(".")) for rdata in answers]
        else:
            lines = _dig(domain, "MX")
            mx_list = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    mx_list.append((int(parts[0]), parts[1].rstrip(".")))
        mx_list.sort()

        import smtplib
        for priority, mx_host in mx_list:
            server = {"priority": priority, "host": mx_host, "banner": None, "tls": None, "provider": _detect_mx_provider(mx_host)}
            try:
                with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
                    server["banner"] = (smtp.ehlo_resp or b"").decode(errors="replace")[:200]
                    try:
                        smtp.starttls()
                        server["tls"] = True
                    except Exception:
                        server["tls"] = False
            except Exception as e:
                server["banner"] = f"failed: {str(e)[:80]}"
            result["servers"].append(server)
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def _detect_providers(includes):
    providers = []
    patterns = {
        "google": "Google Workspace", "_spf.google": "Google Workspace",
        "outlook": "Microsoft 365", "protection.outlook": "Microsoft 365",
        "amazonses": "Amazon SES", "sendgrid": "SendGrid",
        "mailchimp": "Mailchimp", "mandrill": "Mandrill",
        "mimecast": "Mimecast", "proofpoint": "Proofpoint",
        "pphosted": "Proofpoint", "mailgun": "Mailgun",
        "hubspot": "HubSpot", "zendesk": "Zendesk",
    }
    for inc in includes:
        for pattern, provider in patterns.items():
            if pattern in inc.lower() and provider not in providers:
                providers.append(provider)
    return providers


def _detect_mx_provider(mx_host):
    mx = mx_host.lower()
    if "google" in mx or "gmail" in mx: return "Google Workspace"
    if "outlook" in mx or "microsoft" in mx: return "Microsoft 365"
    if "pphosted" in mx or "proofpoint" in mx: return "Proofpoint"
    if "mimecast" in mx: return "Mimecast"
    if "barracuda" in mx: return "Barracuda"
    if "amazonses" in mx: return "Amazon SES"
    return None


# ── DNS enumeration ──────────────────────────────────

def enumerate_dns_records(domain):
    result = {"domain": domain, "records": {}}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]:
        try:
            if USE_DNSPYTHON:
                answers = _resolver.resolve(domain, rtype)
                result["records"][rtype] = [r.to_text() for r in answers]
            else:
                records = _dig(domain, rtype)
                if records:
                    result["records"][rtype] = records
        except Exception:
            continue
    return result


def attempt_zone_transfer(domain):
    result = {"domain": domain, "vulnerable": False, "nameservers": []}
    try:
        if USE_DNSPYTHON:
            ns_answers = _resolver.resolve(domain, "NS")
            ns_list = [str(ns).rstrip(".") for ns in ns_answers]
        else:
            ns_list = [ns.rstrip(".") for ns in _dig(domain, "NS")]

        for ns_host in ns_list:
            entry = {"nameserver": ns_host, "axfr_allowed": False}
            try:
                if USE_DNSPYTHON:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
                    entry["axfr_allowed"] = True
                    result["vulnerable"] = True
                    entry["record_count"] = len(list(zone.nodes.keys()))
                else:
                    out = _run_cmd(["dig", f"@{ns_host}", domain, "AXFR", "+time=10"], timeout=15)
                    if "XFR size" in out or (out.count("\n") > 5 and domain in out):
                        entry["axfr_allowed"] = True
                        result["vulnerable"] = True
                        entry["record_count"] = out.count("\n")
            except Exception as e:
                entry["error"] = str(e)[:100]
            result["nameservers"].append(entry)
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def fingerprint_nameservers(domain):
    result = {"domain": domain, "nameservers": []}
    try:
        if USE_DNSPYTHON:
            ns_answers = _resolver.resolve(domain, "NS")
            ns_list = [str(ns).rstrip(".") for ns in ns_answers]
        else:
            ns_list = [ns.rstrip(".") for ns in _dig(domain, "NS")]

        for ns_host in ns_list:
            info = {"host": ns_host, "ip": None, "software": None, "version_bind": None}
            # Resolve IP
            try:
                if USE_DNSPYTHON:
                    a = _resolver.resolve(ns_host, "A")
                    info["ip"] = str(a[0])
                else:
                    ips = _dig(ns_host, "A")
                    if ips: info["ip"] = ips[0]
            except Exception:
                pass

            # version.bind CHAOS query
            if info["ip"]:
                try:
                    if USE_DNSPYTHON:
                        q = dns.message.make_query("version.bind", "TXT", "CH")
                        r = dns.query.udp(q, info["ip"], timeout=5)
                        for rrset in r.answer:
                            for rd in rrset:
                                info["version_bind"] = rd.to_text().strip('"')
                    else:
                        out = _run_cmd(["dig", f"@{info['ip']}", "version.bind", "TXT", "CH", "+short", "+time=3"])
                        if out: info["version_bind"] = out.strip('"')
                except Exception:
                    pass

            # Detect from hostname
            ns_lower = ns_host.lower()
            if "cloudflare" in ns_lower: info["software"] = "Cloudflare DNS"
            elif "awsdns" in ns_lower: info["software"] = "AWS Route 53"
            elif "azure-dns" in ns_lower: info["software"] = "Azure DNS"
            elif "google" in ns_lower: info["software"] = "Google Cloud DNS"
            elif "nsone" in ns_lower or "ns1" in ns_lower: info["software"] = "NS1"
            elif "domaincontrol" in ns_lower: info["software"] = "GoDaddy DNS"
            elif info.get("version_bind"): info["software"] = info["version_bind"]
            result["nameservers"].append(info)
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


def reverse_dns_sweep(cidr, limit=256):
    result = {"cidr": cidr, "records": [], "total_ips": 0, "resolved": 0}
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = list(network.hosts())[:limit]
        result["total_ips"] = len(hosts)
        for ip in hosts:
            try:
                if USE_DNSPYTHON:
                    rev = dns.reversename.from_address(str(ip))
                    answers = _resolver.resolve(rev, "PTR")
                    for rd in answers:
                        result["records"].append({"ip": str(ip), "ptr": str(rd).rstrip(".")})
                        result["resolved"] += 1
                else:
                    out = _run_cmd(["host", str(ip), "8.8.8.8"], timeout=5)
                    m = re.search(r"pointer\s+(\S+)", out)
                    if m:
                        result["records"].append({"ip": str(ip), "ptr": m.group(1).rstrip(".")})
                        result["resolved"] += 1
            except Exception:
                continue
    except Exception as e:
        result["error"] = str(e)[:200]
    return result


# ── Main ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Service Enumeration CLI (self-contained)")
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--output", default="/tmp/service_enum_out.json", help="Output JSON file")
    parser.add_argument("--services", default="email,dns", help="Comma-separated: email,dns,all")
    parser.add_argument("--reverse-cidr", default=None, help="CIDR for reverse DNS sweep")
    args = parser.parse_args()

    services = args.services.split(",")
    results = {
        "domain": args.domain,
        "timestamp": datetime.utcnow().isoformat(),
        "dns_backend": "dnspython" if USE_DNSPYTHON else "dig-cli",
    }

    print(f"{LOG_PREFIX} Using {'dnspython' if USE_DNSPYTHON else 'dig/host CLI fallback'}", file=sys.stderr)

    if "email" in services or "all" in services:
        print(f"{LOG_PREFIX} Email enumeration for {args.domain}...", file=sys.stderr)
        results["spf"] = check_spf(args.domain)
        results["dmarc"] = check_dmarc(args.domain)
        results["dkim"] = check_dkim(args.domain)
        results["mx"] = enumerate_mx(args.domain)
        score = 0
        if results["spf"].get("exists"): score += 1
        if results["spf"].get("assessment") == "strict": score += 1
        if results["dmarc"].get("exists"): score += 1
        if results["dmarc"].get("assessment") == "strict": score += 1
        if results["dkim"].get("exists"): score += 1
        results["email_security_score"] = f"{score}/5"
        results["providers"] = list(set(
            results["spf"].get("providers", []) +
            [s["provider"] for s in results["mx"].get("servers", []) if s.get("provider")]
        ))

    if "dns" in services or "all" in services:
        print(f"{LOG_PREFIX} DNS enumeration for {args.domain}...", file=sys.stderr)
        results["dns_records"] = enumerate_dns_records(args.domain)
        results["zone_transfer"] = attempt_zone_transfer(args.domain)
        results["nameservers"] = fingerprint_nameservers(args.domain)
        if args.reverse_cidr:
            print(f"{LOG_PREFIX} Reverse DNS sweep on {args.reverse_cidr}...", file=sys.stderr)
            results["reverse_dns"] = reverse_dns_sweep(args.reverse_cidr)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"{LOG_PREFIX} Results written to {args.output}", file=sys.stderr)
    # Also print to stdout for immediate visibility
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
