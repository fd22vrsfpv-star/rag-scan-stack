"""Cert-pivot + ASN-pivot scope expansion.

Companion to `typosquat_agent.py`. Where the typosquat detector generates
lookalike domains, these two passes PIVOT off data the engagement has
ALREADY collected (passive — they send no new traffic to any host, they
only read `recon_findings`):

  * cert_pivot  — a TLS certificate observed on an in-scope host whose SAN
                  list names a domain in a DIFFERENT registrable domain is
                  a strong "same owner, new surface" signal. crt.sh serial /
                  SPKI chaining is a future enhancement (see OPEN_ITEMS);
                  this v1 uses the SAN-overlap signal from stored tlsx /
                  crtsh / certspotter certs.
  * asn_pivot   — the ASN(s) the in-scope hosts resolve into (from asnmap)
                  carry CIDR ranges that often hold adjacent infrastructure.
                  Naive ASN membership is too noisy (a host in AWS is not a
                  pivot), so a range is only suggested when its AS name is
                  NOT a cloud/CDN provider, OR its AS name matches an
                  in-scope org token.

Both passes write `scope_suggestions` rows (method='cert_pivot' /
'asn_pivot', suggested_scope='new_for_review') for operator review. On
accept, the review endpoint promotes the target into the engagement's
`new_for_review` scope — a staging bucket the scope gate refuses dispatch
to (like `typosquats`) until the operator moves it to a live scope.

Idempotent via scope_suggestions.target UNIQUE (ON CONFLICT DO NOTHING).
"""
from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# The staging scope these pivots land in on accept. The scope gate's
# deny-list loader (etl/scope_gate.load_not_in_scope_denylist) reads this
# name so a pivoted target is visible under the engagement but NOT
# dispatchable until the operator promotes it.
NEW_FOR_REVIEW_SCOPE = "new_for_review"

# AS names that are shared hosting / cloud / CDN — a host living here does
# NOT tie the range to our target, so the range is only suggested when the
# AS name ALSO contains an in-scope org token.
CLOUD_CDN_KEYWORDS = {
    "amazon", "aws", "cloudflare", "google", "microsoft", "azure", "akamai",
    "fastly", "digitalocean", "linode", "ovh", "hetzner", "oracle", "gcore",
    "incapsula", "imperva", "stackpath", "cloudfront", "godaddy", "namecheap",
    "squarespace", "wix", "shopify", "automattic", "wordpress", "vercel",
    "netlify", "heroku", "fly.io", "render", "upcloud", "vultr", "leaseweb",
}

CERT_SOURCES = ("tlsx", "crtsh", "certspotter", "cert-chain")
# jsonb keys that may carry subject / SAN names across the cert sources.
_SAN_KEYS = ("subject_an", "dns_names", "sans", "name_value", "san")
_CN_KEYS = ("subject_cn", "common_name", "cn")


# ─── small helpers ──────────────────────────────────────────────────────────

def _registrable(host: str) -> str:
    """Last two labels of a hostname. Imperfect for multi-part TLDs
    (co.uk) but matches the existing _cert_serial_chain parent logic, so
    the two stay consistent."""
    h = (host or "").strip().lower().rstrip(".").lstrip("*.")
    if not h or "." not in h:
        return ""
    parts = h.split(".")
    if len(parts) < 2:
        return ""
    return ".".join(parts[-2:])


def _norm_host(name: str) -> str:
    name = (name or "").strip().lower().rstrip(".").lstrip("*.")
    if "@" in name:
        name = name.split("@")[-1]
    return name


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _org_tokens(parent_domains: set, extra: str = "") -> set:
    """Significant org tokens from the engagement's registrable domains:
    the second-level label (e.g. 'testfire' from testfire.net), lowercased,
    length >= 3 so 'co' / generic labels don't match everything."""
    toks: set = set()
    for d in parent_domains:
        label = (d or "").split(".")[0]
        if len(label) >= 3:
            toks.add(label.lower())
    for w in (extra or "").replace("-", " ").replace("_", " ").split():
        if len(w) >= 3:
            toks.add(w.lower())
    return toks


def _as_range_list(data: dict) -> list:
    """as_range may be a list, a single CIDR string, or absent."""
    rng = data.get("as_range") or data.get("cidr") or data.get("as_ranges")
    if not rng:
        return []
    if isinstance(rng, str):
        return [p.strip() for p in rng.replace(",", " ").split() if p.strip()]
    if isinstance(rng, (list, tuple)):
        out = []
        for r in rng:
            if isinstance(r, str) and r.strip():
                out.append(r.strip())
        return out
    return []


def _valid_cidr(cidr: str) -> str:
    try:
        return str(ipaddress.ip_network(cidr, strict=False))
    except Exception:  # noqa: BLE001
        return ""


# ─── engagement context ─────────────────────────────────────────────────────

def _resolve_scope_context(cur, engagement_id: str) -> dict:
    """Seeds, parent (registrable) domains, known host set and known IP
    set for the engagement — the frame every pivot is judged against."""
    seeds: set = set()
    known_hosts: set = set()
    known_ips: set = set()
    engagement_name = ""
    # Scope targets (domain / url / ip / cidr).
    try:
        cur.execute(
            "SELECT target, target_type FROM public.scope_targets "
            "WHERE engagement_id = %s::uuid "
            "AND target IS NOT NULL AND target <> ''",
            (engagement_id,),
        )
        for r in cur.fetchall():
            tgt, ttype = (r["target"], r["target_type"]) if isinstance(r, dict) else (r[0], r[1])
            tgt = (tgt or "").strip()
            if not tgt:
                continue
            if ttype == "url":
                try:
                    h = urlparse(tgt if "://" in tgt else "//" + tgt).netloc
                    tgt = (h.split("@")[-1].split(":")[0]) or tgt
                except Exception:  # noqa: BLE001
                    pass
            low = _norm_host(tgt)
            if _is_ip(low):
                known_ips.add(low)
            elif "." in low:
                known_hosts.add(low)
                seeds.add(low)
    except Exception as e:  # noqa: BLE001
        logger.warning("scope context scope_targets load failed: %s", e)
    # Assets of the engagement widen the known-host / known-ip sets.
    try:
        cur.execute(
            "SELECT hostname, host(ip) AS ip_address FROM public.assets "
            "WHERE engagement_id = %s::uuid",
            (engagement_id,),
        )
        for r in cur.fetchall():
            hn, ip = (r["hostname"], r["ip_address"]) if isinstance(r, dict) else (r[0], r[1])
            hn = _norm_host(hn or "")
            if hn and "." in hn and not _is_ip(hn):
                known_hosts.add(hn)
            ip = (ip or "").strip()
            if ip and _is_ip(ip):
                known_ips.add(ip)
    except Exception as e:  # noqa: BLE001
        logger.debug("scope context assets load failed: %s", e)
    try:
        cur.execute("SELECT name FROM public.engagements WHERE id = %s::uuid",
                    (engagement_id,))
        row = cur.fetchone()
        if row:
            engagement_name = (row["name"] if isinstance(row, dict) else row[0]) or ""
    except Exception:  # noqa: BLE001
        pass
    parent_domains = {p for p in (_registrable(h) for h in seeds | known_hosts) if p}
    return {
        "seeds": seeds,
        "parent_domains": parent_domains,
        "known_hosts": known_hosts,
        "known_ips": known_ips,
        "engagement_name": engagement_name,
    }


def _existing_suggested_targets(cur) -> set:
    try:
        cur.execute("SELECT target FROM public.scope_suggestions")
        return {(_norm_host(r["target"]) if isinstance(r, dict) else _norm_host(r[0]))
                for r in cur.fetchall()}
    except Exception:  # noqa: BLE001
        return set()


def _write_suggestion(cur, target: str, suggested_scope: str, confidence: float,
                      reasoning: str, method: str, engagement_id: str) -> bool:
    """Insert one scope_suggestions row. Idempotent via UNIQUE(target).
    Returns True on insert, False on conflict / error."""
    try:
        cur.execute(
            "INSERT INTO public.scope_suggestions "
            "(target, suggested_scope, confidence, reasoning, method, engagement_id) "
            "VALUES (%s, %s, %s, %s, %s, %s::uuid) "
            "ON CONFLICT (target) DO NOTHING",
            (target, suggested_scope, float(confidence), reasoning, method,
             engagement_id),
        )
        return cur.rowcount > 0
    except Exception as e:  # noqa: BLE001
        logger.debug("scope_suggestion write failed for %s: %s", target, e)
        return False


# ─── cert pivot ─────────────────────────────────────────────────────────────

def _extract_cert_names(data: dict) -> list:
    """All subject / SAN names from one cert finding's jsonb, normalized."""
    names: set = set()
    for k in _CN_KEYS:
        v = data.get(k)
        if isinstance(v, str) and v:
            names.add(_norm_host(v))
    for k in _SAN_KEYS:
        v = data.get(k)
        if isinstance(v, str) and v:
            # crt.sh name_value is newline / space separated.
            for part in v.replace("\n", " ").split():
                names.add(_norm_host(part))
        elif isinstance(v, (list, tuple)):
            for part in v:
                if isinstance(part, str) and part:
                    names.add(_norm_host(part))
    return [n for n in names if n and "." in n and not _is_ip(n)]


def run_cert_pivot(get_db_fn, engagement_id: str, limit: int = 500) -> dict:
    """Find domains that share a TLS certificate with an in-scope host but
    live in a different registrable domain. Writes method='cert_pivot'
    scope_suggestions. Passive: reads stored certs only."""
    out = {"seeds": 0, "certs_examined": 0, "candidates": 0,
           "suggestions_written": 0, "errors": []}
    with get_db_fn() as c:
        from psycopg2.extras import RealDictCursor
        with c.cursor(cursor_factory=RealDictCursor) as cur:
            ctx = _resolve_scope_context(cur, engagement_id)
            parent_domains = ctx["parent_domains"]
            known_hosts = ctx["known_hosts"]
            out["seeds"] = len(ctx["seeds"])
            if not parent_domains:
                out["errors"].append(
                    "no in-scope domains for this engagement — add a domain "
                    "scope target, then run recon (tlsx/crtsh) before pivoting")
                return out
            already = _existing_suggested_targets(cur)
            # Pull certs; filter to ones observed ON an in-scope host.
            try:
                cur.execute(
                    "SELECT target, data FROM public.recon_findings "
                    "WHERE source = ANY(%s) "
                    "ORDER BY created_at DESC LIMIT 20000",
                    (list(CERT_SOURCES),),
                )
                rows = cur.fetchall()
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"recon_findings read failed: {e}")
                return out
            # candidate -> {hosts: set(seed hosts the cert was on), count}
            candidates: dict = {}
            for r in rows:
                host = _norm_host(r.get("target") or "")
                data = r.get("data") or {}
                if not isinstance(data, dict):
                    continue
                host_reg = _registrable(host)
                # Only certs sitting on OUR surface tie a new domain to us.
                if host_reg not in parent_domains and host not in known_hosts:
                    continue
                out["certs_examined"] += 1
                for name in _extract_cert_names(data):
                    nreg = _registrable(name)
                    if not nreg or nreg in parent_domains:
                        continue  # same org — not a pivot
                    if name in known_hosts:
                        continue
                    entry = candidates.setdefault(name, {"hosts": set()})
                    entry["hosts"].add(host or host_reg)
            out["candidates"] = len(candidates)
            written = 0
            for name in sorted(candidates):
                if written >= limit:
                    break
                if name in already:
                    continue
                hosts = sorted(candidates[name]["hosts"])
                # Shared across several of our hosts is a stronger tie.
                confidence = 0.7 + min(0.2, 0.05 * (len(hosts) - 1))
                via = ", ".join(hosts[:3])
                reasoning = (f"shares a TLS certificate SAN with in-scope "
                             f"host(s) {via}; different registrable domain "
                             f"({_registrable(name)}) — possible same-owner "
                             f"infrastructure")
                if _write_suggestion(cur, name, NEW_FOR_REVIEW_SCOPE,
                                      round(confidence, 3), reasoning,
                                      "cert_pivot", engagement_id):
                    written += 1
            out["suggestions_written"] = written
        c.commit()
    return out


# ─── asn pivot ──────────────────────────────────────────────────────────────

def run_asn_pivot(get_db_fn, engagement_id: str, limit: int = 500) -> dict:
    """Suggest the CIDR ranges of the ASNs the in-scope hosts live in,
    filtered to high precision (cloud/CDN AS names dropped unless the AS
    name matches an in-scope org token). Writes method='asn_pivot'.
    Passive: reads stored asnmap findings only."""
    out = {"seeds": 0, "asns_matched": 0, "candidates": 0,
           "suggestions_written": 0, "errors": []}
    with get_db_fn() as c:
        from psycopg2.extras import RealDictCursor
        with c.cursor(cursor_factory=RealDictCursor) as cur:
            ctx = _resolve_scope_context(cur, engagement_id)
            parent_domains = ctx["parent_domains"]
            known_hosts = ctx["known_hosts"]
            known_ips = ctx["known_ips"]
            out["seeds"] = len(ctx["seeds"])
            org_tokens = _org_tokens(parent_domains, ctx["engagement_name"])
            if not (parent_domains or known_ips):
                out["errors"].append(
                    "no in-scope domains/IPs for this engagement — add scope "
                    "targets and run asnmap before pivoting")
                return out
            already = _existing_suggested_targets(cur)
            # Existing CIDR scope targets, to avoid re-suggesting.
            existing_cidrs: set = set()
            try:
                cur.execute(
                    "SELECT target FROM public.scope_targets "
                    "WHERE target_type = 'cidr'")
                for r in cur.fetchall():
                    cv = _valid_cidr((r["target"] if isinstance(r, dict) else r[0]) or "")
                    if cv:
                        existing_cidrs.add(cv)
            except Exception:  # noqa: BLE001
                pass
            try:
                cur.execute(
                    "SELECT target, data FROM public.recon_findings "
                    "WHERE source = 'asnmap' "
                    "ORDER BY created_at DESC LIMIT 20000")
                rows = cur.fetchall()
            except Exception as e:  # noqa: BLE001
                out["errors"].append(f"recon_findings read failed: {e}")
                return out
            # asn -> {as_name, ranges:set, in_scope:bool, via:set}
            asns: dict = {}
            for r in rows:
                host = _norm_host(r.get("target") or "")
                data = r.get("data") or {}
                if not isinstance(data, dict):
                    continue
                asn = str(data.get("as_number") or data.get("asn") or "").strip()
                if not asn:
                    continue
                as_name = str(data.get("as_name") or data.get("org") or "")
                host_reg = _registrable(host)
                on_scope = (host_reg in parent_domains or host in known_hosts
                            or (_is_ip(host) and host in known_ips))
                entry = asns.setdefault(asn, {"as_name": as_name, "ranges": set(),
                                              "in_scope": False, "via": set()})
                if as_name and not entry["as_name"]:
                    entry["as_name"] = as_name
                for cidr in _as_range_list(data):
                    cv = _valid_cidr(cidr)
                    if cv:
                        entry["ranges"].add(cv)
                if on_scope:
                    entry["in_scope"] = True
                    entry["via"].add(host or host_reg)
            written = 0
            for asn, info in sorted(asns.items()):
                if not info["in_scope"]:
                    continue
                out["asns_matched"] += 1
                as_name_l = (info["as_name"] or "").lower()
                org_hit = any(t in as_name_l for t in org_tokens)
                is_cloud = any(k in as_name_l for k in CLOUD_CDN_KEYWORDS)
                # High precision: drop cloud/CDN ASNs unless the AS name
                # itself matches an in-scope org token.
                if is_cloud and not org_hit:
                    continue
                via = ", ".join(sorted(info["via"])[:3])
                for cidr in sorted(info["ranges"]):
                    if written >= limit:
                        break
                    if cidr in existing_cidrs or cidr in already:
                        continue
                    confidence = 0.8 if org_hit else 0.6
                    reasoning = (f"in-scope host(s) {via} resolve into AS{asn} "
                                 f"({info['as_name'] or 'unknown'}); range "
                                 f"{cidr} may hold adjacent infrastructure")
                    if _write_suggestion(cur, cidr, NEW_FOR_REVIEW_SCOPE,
                                          confidence, reasoning, "asn_pivot",
                                          engagement_id):
                        written += 1
                        out["candidates"] += 1
                if written >= limit:
                    break
            out["suggestions_written"] = written
        c.commit()
    return out
