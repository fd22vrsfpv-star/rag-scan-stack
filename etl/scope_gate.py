"""Engagement scope gating for discovery ingests (G3).

subfinder/dnsx discover new hosts.  Before any discovered host is stamped
with an `engagement_id` (which is what makes the Recon Agent scan it), it
MUST be confirmed in-scope for that engagement.  This module centralizes
that check so parse_subfinder and parse_dnsx behave identically.

Hard invariant: an out-of-scope host is never stamped and never scanned --
it is still recorded (asset + recon_finding) but stays engagement-unscoped.

Matching mirrors app/rag-api/scope_classifier.py (fnmatch for domains,
ipaddress for ip/cidr) so behavior is consistent across the system.
"""
import logging
import re as _re   # dispatch gate: IPv4 extraction
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

logger = logging.getLogger("scope_gate")


def load_engagement_scope(cur, engagement_id):
    """Return a list of (target, target_type) for the engagement's scope.

    Returns [] when engagement_id is falsy or on any query error (fail
    closed -- no scope means nothing is in-scope).  Tolerates both tuple
    and RealDict cursors.
    """
    if not engagement_id:
        return []
    try:
        cur.execute(
            "SELECT target, target_type FROM public.scope_targets "
            "WHERE engagement_id = %s::uuid",
            (engagement_id,),
        )
        rows = cur.fetchall()
    except Exception as e:
        logger.warning("scope load failed for engagement %s: %s", engagement_id, e)
        return []
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append((r.get("target"), r.get("target_type")))
        else:
            out.append((r[0], r[1]))
    return out


def load_ingest_scope(cur):
    """Scope for INGEST-time filtering: (enforce, rows).

    Crawlers and archive-fed tools return hosts nobody asked about — a katana
    crawl of a target's TWiki app followed links to twiki.org, twitter.com and
    youtube.com, and those were stored as engagement findings. Scope was checked
    when choosing what to point a tool AT, never on what came BACK.

    Differs from load_engagement_scope in two deliberate ways:

    * It is the UNION of every configured scope target, not one engagement's.
      These parsers also run for uploads and jobs that carry no engagement id,
      and a finding is legitimate if it is in scope for ANY engagement.

    * `enforce` is False when NO scope is configured anywhere. Failing closed
      there would silently discard every finding on a fresh install, which is
      indistinguishable from a broken parser. With scope configured it is
      enforced, and is_in_scope itself remains fail-closed per host.
    """
    try:
        cur.execute(
            "SELECT target, target_type FROM public.scope_targets "
            "WHERE target IS NOT NULL AND target <> ''"
        )
        rows = cur.fetchall()
    except Exception as e:
        logger.warning("ingest scope load failed: %s", e)
        return False, []

    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append((r.get("target"), r.get("target_type")))
        else:
            out.append((r[0], r[1]))
    return bool(out), out


def host_in_scope(value, enforce, rows):
    """True if `value` (a url or bare host) may be ingested.

    Accepts either form so callers do not each re-derive the host.
    """
    if not enforce:
        return True
    return is_in_scope(_host_from_url(value) or value, rows)


def _host_from_url(value):
    """Extract the bare host from a url/authority string."""
    try:
        netloc = urlparse(value if "://" in value else "//" + value).netloc
        return (netloc.split("@")[-1].split(":")[0]) or value
    except Exception:
        return value


def is_in_scope(host, scope_rows):
    """True if `host` (an IP or hostname) matches any scope target.

    Fail closed: empty/blank host or empty scope returns False.
      - ip      : exact IP match
      - cidr    : host IP inside the network
      - domain  : exact host or any subdomain (`*.domain`)
      - url     : same as domain, on the url's host
      - asn     : not matchable from a host alone -> ignored
    """
    if not host or not scope_rows:
        return False
    h = host.strip().lower().rstrip(".")
    if not h:
        return False
    try:
        host_ip = ip_address(h)
    except ValueError:
        host_ip = None

    for target, ttype in scope_rows:
        if not target:
            continue
        t = target.strip().lower().rstrip(".")
        tt = (ttype or "").lower()
        try:
            if tt == "ip":
                if host_ip is not None and h == t:
                    return True
            elif tt == "cidr":
                if host_ip is not None and host_ip in ip_network(t, strict=False):
                    return True
            elif tt == "domain":
                if h == t or fnmatch(h, "*." + t):
                    return True
            elif tt == "url":
                turl = _host_from_url(t)
                if turl and (h == turl or fnmatch(h, "*." + turl)):
                    return True
            # 'asn' cannot be matched from a host string alone -> skip
        except (ValueError, TypeError):
            continue
    return False


# ── Dispatch-side gate (shared by every service) ──────────────────────────
#
# Everything above answers "should I STORE this finding?". Everything below
# answers "may I SEND traffic at this host?" — the authorisation question.
#
# This module is the single implementation. It briefly existed three times over
# (etl, the BFF, kali-listener) because container build contexts could not reach
# it; `./etl` is now bind-mounted into every service that dispatches, so they
# all import these functions instead of carrying a copy.
#
# Pure stdlib on purpose: adding a dependency here would have to be installed in
# every one of those images.

# Bare IPv4 literals. Hostnames are deliberately NOT extracted from command
# lines: wordlist paths, tool names and version strings produce false positives,
# and a gate that blocks legitimate work gets switched off.
_IPV4_RE = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Addresses that mean "this machine", not "a target": listener binds, local
# callbacks, and the unspecified address.
_SELF_ADDRS = ("127.", "0.0.0.0", "::1")


def load_dispatch_scope(cur, engagement_id=None):
    """Scope rows for an authorisation decision.

    Prefers the engagement's own scope; falls back to the union of all
    configured targets so a dispatch with no engagement context is still
    checked rather than waved through. Returns (rows, source).

    On ANY error returns ([], "unavailable") — the caller must treat an empty
    result as "refuse", never as "no restrictions".
    """
    try:
        if engagement_id:
            rows = load_engagement_scope(cur, engagement_id)
            if rows:
                return rows, "engagement"
        cur.execute("SELECT target, target_type FROM public.scope_targets")
        out = []
        for r in cur.fetchall():
            if isinstance(r, dict):
                out.append((r.get("target"), r.get("target_type")))
            else:
                out.append((r[0], r[1]))
        return [r for r in out if r[0]], "all-engagements"
    except Exception as e:
        logger.warning("dispatch scope load failed: %s", e)
        return [], "unavailable"


def hosts_in_command(command):
    """IPv4 literals a command will actually talk to, self-addresses removed."""
    found = set(_IPV4_RE.findall(command or ""))
    return sorted(h for h in found
                  if not any(h.startswith(p) or h == p for p in _SELF_ADDRS))


def check_dispatch(target, scope_rows, command=""):
    """Return a refusal string when this dispatch must be refused, else None.

    Checks the declared target AND any IPv4 literal in the command, so omitting
    the target and naming the host in the command line is not a way around it.

    Fails CLOSED on an empty scope: an unconfigured scope is a setup mistake,
    not permission to scan anything.
    """
    if not scope_rows:
        return ("no scope targets are configured — refusing to dispatch. "
                "Configure the engagement scope first.")
    if target and not is_in_scope(str(target), scope_rows):
        return f"target {target} is not in the configured scope"
    for ip in hosts_in_command(command):
        if not is_in_scope(ip, scope_rows):
            return f"command references {ip}, which is not in the configured scope"
    return None
