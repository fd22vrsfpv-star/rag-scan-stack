"""WHOIS field extraction, shared by osint_runner and node_manager.

node_manager's remote-WHOIS branch tried to borrow osint_runner's parsers:

    from osint_runner.osint_runner import _parse_whois_domain, _parse_whois_ip

inside `except ImportError:`. The module is not in node-manager's image
(`docker exec node-manager python -c "import osint_runner"` →
`ModuleNotFoundError`), so the import always failed — and the names it bound
were never read anyway. Underneath it was a re-typed, shorter copy of the same
field maps: 8 fields against 11 for a domain, with the domain and IP maps
merged into one, so a remote WHOIS recorded `org` and `registrar` for a domain
and silently dropped expiry, registrant and DNSSEC.

Shipping the whole of `osint_runner.py` into the image to fix that would be a
poor trade: it is 5,267 lines, builds a FastAPI app at import time and pulls in
`tool_job`, `log_manager`, `validation` and `service_enum`. These two functions
are pure string work with no dependencies at all, so they belong here —
`common/` is already bind-mounted into every service that needs it, which is
also why a change lands without a rebuild.

`osint_runner._parse_whois_domain` / `_parse_whois_ip` now delegate here, so
there is one implementation rather than two that agree today.
"""
from __future__ import annotations

# Fields whose value is a LIST — a record legitimately carries several of each.
# Everything else keeps the first value seen.
_MULTI = {"name_servers", "status"}

_DOMAIN_FIELDS = {
    "registrar": ["Registrar:", "registrar:"],
    "org": ["Registrant Organization:", "org:", "OrgName:"],
    "creation_date": ["Creation Date:", "created:", "Registration Date:"],
    "expiry_date": ["Registry Expiry Date:", "Expiry Date:", "paid-till:"],
    "updated_date": ["Updated Date:", "last-modified:"],
    "name_servers": ["Name Server:", "nserver:"],
    "registrant_name": ["Registrant Name:"],
    "registrant_email": ["Registrant Email:", "e-mail:"],
    "registrant_country": ["Registrant Country:", "Registrant State/Province:"],
    "dnssec": ["DNSSEC:"],
    "status": ["Domain Status:", "status:"],
}

_IP_FIELDS = {
    "org": ["OrgName:", "org-name:", "Organization:", "org:", "descr:"],
    "org_id": ["OrgId:", "org:"],
    "net_range": ["NetRange:", "inetnum:"],
    "cidr": ["CIDR:", "route:"],
    "net_name": ["NetName:", "netname:"],
    "country": ["Country:", "country:"],
    "abuse_email": ["OrgAbuseEmail:", "abuse-mailbox:"],
    "tech_email": ["OrgTechEmail:", "tech-c:"],
    "ref": ["Ref:", "source:"],
    "asn": ["OriginAS:", "origin:"],
    "net_handle": ["NetHandle:"],
    "parent": ["Parent:"],
}


def _extract(raw: str, field_map: dict) -> dict:
    """First (or every, for _MULTI) value of each field, by line prefix.

    Case-insensitive on the label, because registries disagree about it
    (`OrgName:` vs `org-name:`), and split on the FIRST colon only, because
    values contain colons — a URL, an IPv6 address, a timestamp.
    """
    out: dict = {}
    lines = (raw or "").splitlines()
    for key, patterns in field_map.items():
        values: list = []
        for pat in patterns:
            for line in lines:
                if line.strip().lower().startswith(pat.lower()):
                    val = line.split(":", 1)[1].strip()
                    if val and val not in values:
                        values.append(val)
        if values:
            out[key] = values if key in _MULTI else values[0]
    return out


def parse_whois_domain(raw: str, domain: str) -> dict:
    """Parse WHOIS output for a domain."""
    parsed = {"raw_length": len(raw or ""), "domain": domain, "type": "domain"}
    parsed.update(_extract(raw, _DOMAIN_FIELDS))
    return parsed


def parse_whois_ip(raw: str, ip: str) -> dict:
    """Parse WHOIS output for an IP address (ARIN/RIPE/APNIC format)."""
    parsed = {"raw_length": len(raw or ""), "ip": ip, "type": "ip"}
    parsed.update(_extract(raw, _IP_FIELDS))
    return parsed


def parse_whois(raw: str, target: str, is_ip: bool) -> dict:
    """Dispatch on the target kind. The caller already knows which it has."""
    return parse_whois_ip(raw, target) if is_ip else parse_whois_domain(raw, target)
