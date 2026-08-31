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


def is_halted(cur, engagement_id=None):
    """Global kill-switch check. Returns (halted, reason).

    A 'global' halt stops every dispatch; an engagement-scoped halt stops only
    that engagement's. Fail SAFE here (return not-halted on a DB error) because
    load_dispatch_scope — which calls this — ALREADY fails closed on a DB error
    (returns ([], "unavailable") → refuse). So a DB outage refuses via that path;
    this check only decides the halted case when the DB is reachable.
    """
    try:
        keys = ["global"]
        if engagement_id:
            keys.append(str(engagement_id))
        cur.execute(
            "SELECT scope, reason FROM public.platform_control "
            "WHERE halted = true AND scope = ANY(%s) LIMIT 1",
            (keys,),
        )
        row = cur.fetchone()
        if not row:
            return False, None
        scope = row.get("scope") if isinstance(row, dict) else row[0]
        reason = row.get("reason") if isinstance(row, dict) else row[1]
        return True, f"platform HALTED ({scope}): {reason or 'no reason given'}"
    except Exception as e:  # table missing / transient — see docstring
        logger.debug("halt check unavailable: %s", e)
        return False, None


def over_budget(cur, engagement_id=None):
    """Blast-radius check. Returns (exceeded, reason).

    A scope is over budget when its platform_control row has a scan_budget set
    and scans_used has reached it. Bounds the AUTONOMOUS loop's reach; the loop
    increments scans_used per dispatch (see /control/note-dispatch). Fail SAFE
    (not-exceeded on error) for the same reason as is_halted — load_dispatch_scope
    already fails closed on a DB outage.
    """
    try:
        keys = ["global"]
        if engagement_id:
            keys.append(str(engagement_id))
        cur.execute(
            "SELECT scope, scan_budget, scans_used FROM public.platform_control "
            "WHERE scan_budget IS NOT NULL AND scans_used >= scan_budget "
            "AND scope = ANY(%s) LIMIT 1",
            (keys,),
        )
        row = cur.fetchone()
        if not row:
            return False, None
        scope = row.get("scope") if isinstance(row, dict) else row[0]
        used = row.get("scans_used") if isinstance(row, dict) else row[2]
        budget = row.get("scan_budget") if isinstance(row, dict) else row[1]
        return True, f"scan budget exhausted ({scope}): {used}/{budget}"
    except Exception as e:
        logger.debug("budget check unavailable: %s", e)
        return False, None


def load_dispatch_scope(cur, engagement_id=None):
    """Scope rows for an authorisation decision.

    Prefers the engagement's own scope; falls back to the union of all
    configured targets so a dispatch with no engagement context is still
    checked rather than waved through. Returns (rows, source).

    On ANY error returns ([], "unavailable") — the caller must treat an empty
    result as "refuse", never as "no restrictions".

    Two platform controls are enforced here, at the one chokepoint every gated
    dispatcher passes: the KILL-SWITCH (halt → ([], "halted")) and the
    BLAST-RADIUS budget (over budget → ([], "budget-exceeded")). Because every
    caller treats an empty scope as "refuse", one place stops all dispatch.
    """
    try:
        halted, _reason = is_halted(cur, engagement_id)
        if halted:
            return [], "halted"
        exceeded, _b = over_budget(cur, engagement_id)
        if exceeded:
            return [], "budget-exceeded"
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


def check_dispatch(target, scope_rows, command="", aliases=None):
    """Return a refusal string when this dispatch must be refused, else None.

    Checks the declared target AND any IPv4 literal in the command, so omitting
    the target and naming the host in the command line is not a way around it.

    `aliases` (from load_host_aliases) lets a host match the scope under another
    observed identity — the scope lists an IP, the request names the hostname.
    Omitting it is safe but STRICTER, and inconsistent strictness between paths
    is what this parameter exists to remove.

    Fails CLOSED on an empty scope: an unconfigured scope is a setup mistake,
    not permission to scan anything.
    """
    if not scope_rows:
        return ("no scope targets are configured — refusing to dispatch. "
                "Configure the engagement scope first.")
    if target and not is_in_scope_with_aliases(str(target), scope_rows, aliases):
        return f"target {target} is not in the configured scope"
    for ip in hosts_in_command(command):
        if not is_in_scope_with_aliases(ip, scope_rows, aliases):
            return f"command references {ip}, which is not in the configured scope"
    return None


def check_targets_file(path, scope_rows, limit=10000):
    """Refusal string if any target in a targets file is out of scope, else None.

    The runner services write their targets to a file and hand the path to the
    tool, so the file — not an argument — is what actually determines where
    packets go. Comments and blanks are ignored; URLs are reduced to their host.

    A file that cannot be read is a refusal, not a pass: if we cannot tell what
    a tool is about to be pointed at, we do not run it.
    """
    if not scope_rows:
        return ("no scope targets are configured — refusing to dispatch. "
                "Configure the engagement scope first.")
    try:
        with open(path, "r", errors="replace") as fh:
            lines = [ln.strip() for ln in fh.readlines()[:limit]]
    except OSError as e:
        return f"targets file {path} is unreadable ({e}) — refusing to dispatch"
    bad = []
    for raw in lines:
        if not raw or raw.startswith("#"):
            continue
        host = _host_from_url(raw) if "://" in raw else raw.split("/")[0].split(":")[0]
        if host and not is_in_scope(host, scope_rows):
            bad.append(host)
    if bad:
        uniq = sorted(set(bad))
        return (f"{len(uniq)} target(s) not in the configured scope: "
                f"{', '.join(uniq[:5])}{'…' if len(uniq) > 5 else ''}")
    return None


def load_host_aliases(cur, host):
    """Observed ip<->hostname pairings for `host`, from the assets table.

    A host can be in scope under a different identity: the scope lists an IP
    but the request names the hostname, or vice versa. Without this the same
    target gets two different answers depending on which path asked —
    routers/scans.py resolved aliases and every other caller did not, so a scan
    the launcher accepted would be blocked when dispatched from a
    recommendation.

    Deliberately uses OBSERVED pairings from assets rather than live DNS: a
    resolver answer is attacker-influencable, and letting a DNS record talk a
    host into scope would defeat the gate.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return set()
    aliases = {h}
    if h in ("localhost", "127.0.0.1", "::1"):
        return aliases | {"localhost", "127.0.0.1", "::1"}
    try:
        cur.execute(
            """
            SELECT host(ip)::text AS ip, lower(coalesce(hostname, '')) AS hostname
              FROM public.assets
             WHERE host(ip) = %s OR lower(coalesce(hostname, '')) = %s
            """,
            (h, h),
        )
        for row in cur.fetchall():
            ip, hn = (row["ip"], row["hostname"]) if isinstance(row, dict) else (row[0], row[1])
            aliases |= {x for x in (str(ip or "").lower(), str(hn or "").lower()) if x}
    except Exception as e:
        # An alias lookup failure must NARROW, never widen: fall back to the
        # host as given rather than pretending it has no other identity.
        logger.warning("alias lookup failed for %r: %s", host, e)
    return aliases


def is_in_scope_with_aliases(host, scope_rows, aliases=None):
    """is_in_scope(), also accepting any known alias of `host`."""
    if is_in_scope(host, scope_rows):
        return True
    return any(is_in_scope(a, scope_rows) for a in (aliases or set()) if a)

# ── Self-contained enforcement for services with no gate of their own ────────
#
# check_dispatch() needs scope rows, and loading them needs a cursor, so every
# caller previously had to wire up its own DB access. That is why 16 modules
# subprocess straight to a target with no check at all: the gate was more work
# to adopt than to skip.
#
# This does the whole thing — connect, load, check — so a caller adds one line
# before it sends traffic. psycopg2 is imported lazily so this module keeps its
# stdlib-only import surface for the parsers that only need the matchers.
_ENFORCE_CACHE = {"rows": None, "at": 0.0}
ENFORCE_CACHE_TTL = 30


def enforce_target_scope(target, command="", dsn=None, cache_ttl=None,
                         engagement_id=None):
    """Return a refusal string when this target must NOT be contacted, else None.

    Usage, immediately before dispatch:

        refusal = enforce_target_scope(target, " ".join(cmd))
        if refusal:
            logger.warning("REFUSED %s: %s", target, refusal)
            return ...

    FAILS CLOSED. An unreadable scope, a missing DSN or a DB error all produce a
    refusal, because "cannot check" and "is authorised" must never look the same
    to a tool that is about to send packets. A transient failure is deliberately
    NOT cached, so one blip does not refuse everything for the whole TTL.
    """
    import os
    import time

    ttl = ENFORCE_CACHE_TTL if cache_ttl is None else cache_ttl
    now = time.time()
    rows = _ENFORCE_CACHE["rows"]
    if rows is None or now - _ENFORCE_CACHE["at"] >= ttl:
        conn_str = dsn or os.environ.get("DB_DSN")
        if not conn_str:
            return ("scope cannot be verified: DB_DSN is unset — refusing to "
                    "send traffic")
        try:
            import psycopg2
        except ImportError as exc:
            return f"scope cannot be verified: psycopg2 unavailable ({exc})"
        try:
            conn = psycopg2.connect(conn_str)
            try:
                with conn.cursor() as cur:
                    rows, _source = load_dispatch_scope(cur, engagement_id)
            finally:
                conn.close()
        except Exception as exc:
            return f"scope cannot be verified: {type(exc).__name__}: {exc}"
        _ENFORCE_CACHE.update({"rows": rows, "at": now})

    # check_dispatch already returns "refusal string or None" — the same
    # contract this function has, so pass it straight through rather than
    # inventing a second convention.
    return check_dispatch(target, rows, command)
