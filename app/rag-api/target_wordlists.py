"""Per-target credential candidate lists: discovered, default, then generic.

WHY THIS EXISTS
---------------
The curated shortlist is 25 generic passwords and does not contain `msfadmin` —
yet `msfadmin:msfadmin` is a credential this engagement ALREADY recovered on ftp
and telnet. Meanwhile enum4linux-ng enumerated **35 usernames** on the same host
through a null session, and none of them reached the database: the vault holds
four (anonymous, ftp, msfadmin, user).

So every brute-force run has been fired with a generic list while the two
highest-value sources sat unused:

  1. usernames already discovered ON THIS HOST
  2. the documented default pair for the SERVICE
  3. the username itself as the password — the account-shaped default, which is
     exactly how msfadmin:msfadmin works

Ordering matters as much as content. hydra tries candidates in file order, so
discovered and default entries go FIRST: if the pair is going to be found, it is
found in the first few hundred attempts rather than after the generic tail. A
list is only useful if it finishes, which is the whole lesson of the 15,875-hour
run.

PROVENANCE
----------
Every entry records where it came from (`discovered`, `service_default`,
`common`, `curated`, `username_as_password`). Without that, a recovered
credential cannot be traced back to the evidence that suggested it, and the
operator cannot tell a measured username from a guess.
"""
import os
import re
from typing import Dict, List, Optional, Tuple

DEFAULTS_FILE = os.environ.get("DEFAULT_CREDS_FILE",
                               "/knowledge/default_credentials.yaml")
# rag-api mounts ./wordlists read-write; kali-listener mounts it read-only, which
# is why generated lists go here rather than into the image.
GENERATED_DIR = os.environ.get("GENERATED_WORDLIST_DIR", "/wordlists/generated")

# The curated tail is READ here, in rag-api, so the paths must be ones rag-api
# can see. /usr/share/wordlists/... exists only in kali-listener: pointing at it
# made `_read_list` return [] on every call, so `include_curated=True` silently
# added nothing and the provenance mix showed no `curated` entries at all.
# The host mount carries its own copy of seclists, with the same two files.
# Candidates are tried, and searched for, in more than one place.
_CURATED_CANDIDATES = {
    "passwords": (
        "/wordlists/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt",
        "/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt",
    ),
    "users": (
        "/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
    ),
}


def _curated_path(kind: str) -> Optional[str]:
    for path in _CURATED_CANDIDATES.get(kind, ()):
        if os.path.exists(path):
            return path
    return None

# A username must be a plausible account name before it goes in a list. Tool
# output is full of fragments, and a header cell stored as a username produces a
# list that wastes attempts on garbage — the same class of error as a share
# called "Permissions".
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._$@\\-]{1,64}$")
# Header cells and sentinels — never account names.
#
# `user` was in this set and that was WRONG: it is a real local account on this
# engagement's target, with a VERIFIED password already in the vault. Including
# it here rejected a known-good username from the identity list and from every
# generated wordlist. A word being a plausible column header does not make it an
# implausible account name, and "user" is one of the most common accounts there
# is. Only strings that cannot be an account name belong here.
_NOT_USERNAMES = {
    "username", "usernames", "name", "account", "login", "password",
    "share", "sharename", "permissions", "remark", "comment",
    "null", "none", "true", "false", "unknown", "n/a",
}


def load_defaults(path: str = None) -> dict:
    try:
        import yaml
    except ImportError:
        return {}
    try:
        with open(path or DEFAULTS_FILE, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except OSError:
        return {}


def _plausible_username(name: str) -> bool:
    n = (name or "").strip()
    if not n or len(n) > 64:
        return False
    if n.lower() in _NOT_USERNAMES:
        return False
    if n.strip("-=_ ") == "":          # a separator row
        return False
    return bool(_USERNAME_RE.match(n))


def service_for_port(defaults: dict, port, service_hint: str = "") -> Optional[str]:
    """Service key from an explicit hint, else from the port number."""
    services = (defaults.get("services") or {})
    hint = (service_hint or "").strip().lower()
    if hint in services:
        return hint
    for name, spec in services.items():
        if hint and (hint.startswith(name) or name in hint):
            return name
        if port and int(port) in [int(p) for p in (spec.get("ports") or [])]:
            return name
    return None


def harvest_usernames(cur, target: str) -> Dict[str, List[str]]:
    """Usernames known for this host, by source.

    Reads the stored tables AND re-derives from captured tool output, because
    extraction currently lands nowhere: 35 enum4linux-ng usernames exist only
    inside `tool_executions.output`. Deterministic regexes only — no model call —
    so this is cheap enough to run on every build and yields the same list twice.
    """
    found: Dict[str, List[str]] = {"vault": [], "findings": [], "identities": [],
                                   "extracted": []}

    # credential_vault has NO host column, so these are engagement-wide rather
    # than host-scoped. That is the right behaviour for a spray candidate — a
    # username seen anywhere in the engagement is worth trying here — but it is
    # a weaker claim than the other two sources, and the provenance says so.
    cur.execute("""
        SELECT DISTINCT username FROM credential_vault
         WHERE COALESCE(username, '') <> ''
    """)
    found["vault"] = [r[0] if not isinstance(r, dict) else r["username"]
                      for r in cur.fetchall()]

    cur.execute("""
        SELECT DISTINCT username FROM credential_findings
         WHERE COALESCE(username, '') <> '' AND host(ip) = %s
    """, (target,))
    found["findings"] = [r[0] if not isinstance(r, dict) else r["username"]
                         for r in cur.fetchall()]

    # Identities — the DURABLE record. `extracted` below re-derives the same
    # names from raw output, which works only while that output is still stored;
    # once artifacts are pruned or skipped, this is the source that survives.
    try:
        cur.execute("""
            SELECT DISTINCT display_name FROM identities
             WHERE COALESCE(display_name, '') <> ''
               AND (domain = %s OR identifier ILIKE '%%@' || %s)
        """, (target, target))
        found["identities"] = [r[0] if not isinstance(r, dict)
                               else r["display_name"] for r in cur.fetchall()]
    except Exception:
        pass    # a missing identities table must not empty the list

    # Re-derive from output. This is the 35.
    try:
        import extractor_specs as es
        cur.execute("""
            SELECT tool, COALESCE(output, '') AS output
              FROM tool_executions
             WHERE target = %s AND octet_length(COALESCE(output, '')) > 0
             ORDER BY started_at DESC LIMIT 200
        """, (target,))
        for row in cur.fetchall():
            tool = row[0] if not isinstance(row, dict) else row["tool"]
            output = row[1] if not isinstance(row, dict) else row["output"]
            spec = es.spec_for(tool)
            if not spec:
                continue
            got = es.run_deterministic(spec, output)
            for name in (got.get("users") or []):
                found["extracted"].append(name)
    except Exception:
        pass    # extraction is an enrichment; its absence must not empty the list

    for key in found:
        seen, uniq = set(), []
        for n in found[key]:
            n = (n or "").strip()
            if _plausible_username(n) and n.lower() not in seen:
                seen.add(n.lower())
                uniq.append(n)
        found[key] = uniq
    return found


def _read_list(path: str, limit: int = 5000) -> List[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for _, ln in zip(range(limit), fh)]
    except OSError:
        return []


def build_lists(cur, target: str, port=None, service_hint: str = "",
                include_curated: bool = True,
                defaults_path: str = None) -> dict:
    """Compose the user and password candidate lists for one target/service.

    Returns both lists plus per-entry provenance and the counts that the
    candidate-space guard will judge.
    """
    defaults = load_defaults(defaults_path)
    svc = service_for_port(defaults, port, service_hint)
    svc_spec = ((defaults.get("services") or {}).get(svc) or {}) if svc else {}
    common = defaults.get("common") or {}

    harvested = harvest_usernames(cur, target)
    discovered = []
    for key in ("findings", "vault", "identities", "extracted"):
        discovered.extend(harvested.get(key) or [])

    users, u_prov = [], {}
    passwords, p_prov = [], {}

    def add(seq, target_list, prov_map, source):
        for item in seq or []:
            item = item if isinstance(item, str) else str(item)
            key = item
            if key in prov_map:
                continue        # first source wins, so order = priority
            prov_map[key] = source
            target_list.append(item)

    # Order IS priority: hydra reads the file top to bottom.
    add(discovered, users, u_prov, "discovered")
    add(svc_spec.get("usernames"), users, u_prov, "service_default")
    add(common.get("usernames"), users, u_prov, "common")
    curated_users_path = _curated_path("users") if include_curated else None
    if curated_users_path:
        add(_read_list(curated_users_path), users, u_prov, "curated")

    add(svc_spec.get("passwords"), passwords, p_prov, "service_default")
    # The account-shaped default: msfadmin:msfadmin is exactly this, and the
    # generic 25-entry shortlist could never have produced it.
    if defaults.get("username_as_password", True):
        add(users, passwords, p_prov, "username_as_password")
    add(common.get("passwords"), passwords, p_prov, "common")
    curated_pw_path = _curated_path("passwords") if include_curated else None
    if curated_pw_path:
        add(_read_list(curated_pw_path), passwords, p_prov, "curated")

    # Drop candidates the domain cannot accept. A guaranteed miss still burns
    # an attempt, and against a lockout threshold attempts are the scarce thing.
    dropped, min_len, min_why = [], None, None
    try:
        import scan_parameters as _sp
        min_len, min_why = _sp.min_password_length(cur, target, svc or "")
    except Exception:
        min_len = None
    if min_len:
        keep = []
        for pw in passwords:
            if len(pw) < min_len:
                dropped.append(pw)
                p_prov.pop(pw, None)
            else:
                keep.append(pw)
        passwords = keep

    return {
        "target": target, "port": port, "service": svc,
        "users": users, "passwords": passwords,
        "min_password_length": min_len,
        "min_password_length_reason": min_why,
        "passwords_dropped_below_minimum": len(dropped),
        "user_provenance": u_prov, "password_provenance": p_prov,
        "counts": {
            "users": len(users), "passwords": len(passwords),
            "candidates": len(users) * len(passwords) if users else len(passwords),
            "discovered_usernames": len(set(discovered)),
        },
        "harvested": {k: len(v) for k, v in harvested.items()},
        "curated_sources": {"users": curated_users_path,
                            "passwords": curated_pw_path},
        "notes": svc_spec.get("notes"),
    }


def _safe_component(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(text or "unknown"))[:60]


def write_lists(built: dict, out_dir: str = None) -> dict:
    """Write both lists and return the paths the tools will read.

    A trailing newline per entry, and a BLANK first line is preserved when a
    service's defaults include one — an empty password is a real candidate (a
    blank mysql root and an anonymous ftp are both exactly that), so it must
    survive being written to a file.
    """
    out_dir = out_dir or GENERATED_DIR
    os.makedirs(out_dir, exist_ok=True)
    tag = f"{_safe_component(built['target'])}_{_safe_component(built.get('service') or built.get('port') or 'any')}"
    paths = {}
    for kind, entries in (("users", built["users"]), ("passwords", built["passwords"])):
        path = os.path.join(out_dir, f"{kind}_{tag}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(f"{e}\n")
        paths[kind] = path
        paths[f"{kind}_lines"] = len(entries)
    return paths


# ── substitution ────────────────────────────────────────────────────────────

# Placeholders a brute-force command may carry. The listener REFUSES any
# unresolved {placeholder}, so every one of these must be filled before dispatch
# — which is fail-safe (it declines rather than running something wrong) but
# still a broken dispatch, so resolution must never simply give up.
USER_LIST_TOKEN = "{user_list}"
PASSWORD_LIST_TOKEN = "{password_list}"

# Where the resolver falls back to. These are the STATIC curated lists inside
# kali-listener, so a fallback still runs 17 x 25 = 425 candidates rather than
# rockyou's 243,854,783. Never fall back to a list that cannot finish.
STATIC_USER_LIST = ("/usr/share/wordlists/seclists/Usernames/"
                    "top-usernames-shortlist.txt")
STATIC_PASSWORD_LIST = ("/usr/share/wordlists/seclists/Passwords/"
                        "Common-Credentials/top-passwords-shortlist.txt")


def needs_lists(command: str) -> bool:
    return bool(command) and (USER_LIST_TOKEN in command
                              or PASSWORD_LIST_TOKEN in command)


def resolve_command(cur, command: str, target: str, port=None,
                    service_hint: str = "", build: bool = True) -> dict:
    """Fill {user_list}/{password_list} with real, readable paths.

    Prefers freshly built per-target lists — 35 discovered usernames and the
    service's own defaults, with the username-as-password rule that produces
    msfadmin:msfadmin. Falls back to the STATIC short lists if building fails,
    never to a list that cannot finish, and never leaves a placeholder for the
    listener to refuse.

    The `source` field says which happened, because a silent fallback would hide
    that the discovered usernames — the entire point — were not used.
    """
    if not needs_lists(command):
        return {"command": command, "changed": False, "source": "not_needed",
                "paths": {}}

    paths, source, problem = {}, "static_fallback", None
    if build:
        try:
            built = build_lists(cur, target, port=port, service_hint=service_hint)
            written = write_lists(built)
            paths = {"users": written["users"], "passwords": written["passwords"]}
            source = "generated"
        except Exception as exc:            # noqa: BLE001
            problem = f"{type(exc).__name__}: {exc}"

    if source != "generated":
        paths = {"users": STATIC_USER_LIST, "passwords": STATIC_PASSWORD_LIST}

    out = command.replace(USER_LIST_TOKEN, paths["users"]) \
                 .replace(PASSWORD_LIST_TOKEN, paths["passwords"])
    return {"command": out, "changed": out != command, "source": source,
            "paths": paths, "problem": problem,
            "counts": built["counts"] if source == "generated" else None}


# ── enumerated accounts as durable identities ──────────────────────────────

def import_enumerated_identities(cur, dry_run=True, target=None, limit=2000):
    """Record enumerated usernames as identities with no credential yet.

    enum4linux and enum4linux-ng enumerated 35 accounts on 192.168.1.150 through
    a null session, and the only durable record was the raw text: the vault held
    four names, all of them ones a password had already been found for. Every
    later question — "which accounts have we not tried?", "spray this list" —
    had to re-parse tool output to get an answer.

    `identities` is the right home: a registry of principals, independent of
    whether a credential is known. Two deliberate choices:

    * **status='unknown'**, not 'active'. The column is an ACCOUNT-state field
      (active/disabled/unknown/deleted) and enumeration proves only that the
      account exists — not that it can be used. A working login is what proves
      'active', which is what the credential bridge sets.
    * **status is never downgraded.** Re-importing must not turn a
      proven-'active' account back into 'unknown', so the upsert keeps the
      stronger value.

    Whether a password is known is NOT stored here. `v_identity_credential_state`
    derives it by joining the vault and the verified findings, because a stored
    flag goes stale the moment a password is cracked — and a stale flag would
    send the operator to re-attack an account already owned.

    No scope gate: this records hosts we have ALREADY scanned, from output
    already in the database. It sends no traffic and proposes nothing. The
    forward-looking path — building an attack list — is gated, in
    `/wordlists/build-target`.
    """
    where, params = ["octet_length(COALESCE(output, '')) > 0",
                     "COALESCE(target, '') <> ''"], []
    if target:
        where.append("target = %s")
        params.append(target)
    params.append(int(limit))
    cur.execute(f"""
        SELECT tool, target, port, service, COALESCE(output, '') AS output
          FROM tool_executions
         WHERE {' AND '.join(where)}
         ORDER BY started_at DESC
         LIMIT %s
    """, params)
    rows = [dict(r) if isinstance(r, dict) else
            {"tool": r[0], "target": r[1], "port": r[2], "service": r[3],
             "output": r[4]} for r in cur.fetchall()]

    try:
        import extractor_specs as es
    except ImportError:
        return {"error": "extractor_specs unavailable", "found": 0}

    # (host, username) -> {tools, services}
    accounts = {}
    for r in rows:
        spec = es.spec_for(r["tool"])
        if not spec:
            continue
        fields = es.run_deterministic(spec, r["output"])
        for name in (fields.get("users") or []):
            name = (name or "").strip()
            if not _plausible_username(name):
                continue
            slot = accounts.setdefault((r["target"], name),
                                       {"tools": set(), "services": set()})
            slot["tools"].add(r["tool"])
            if r.get("service") and r.get("port"):
                slot["services"].add(f"{r['service']}/{r['port']}")

    planned = []
    for (host, name), meta in sorted(accounts.items()):
        planned.append({
            "provider": "local",
            "identifier": f"{name}@{host}",
            "display_name": name,
            "host": host,
            "sources": sorted(meta["tools"]),
            "tags": sorted({f"host:{host}"} | {f"service:{s}"
                                               for s in meta["services"]}
                           | {"discovery:enumerated"}),
        })

    inserted = updated = 0
    if not dry_run and planned:
        from psycopg2.extras import Json
        for p in planned:
            cur.execute("""
                INSERT INTO identities
                    (provider, identifier, display_name, principal_type,
                     status, domain, sources, tags, first_seen, last_seen, raw)
                VALUES (%s, %s, %s, 'user', 'unknown', %s, %s, %s,
                        now(), now(), %s)
                ON CONFLICT (provider, lower(identifier)) DO UPDATE
                   SET last_seen = now(),
                       updated_at = now(),
                       -- Never downgrade a proven-active account.
                       status = CASE WHEN identities.status = 'active'
                                     THEN identities.status
                                     ELSE EXCLUDED.status END,
                       sources = (SELECT array_agg(DISTINCT s ORDER BY s)
                                    FROM unnest(COALESCE(identities.sources,
                                                         ARRAY[]::text[])
                                                || EXCLUDED.sources) s),
                       tags    = (SELECT array_agg(DISTINCT t ORDER BY t)
                                    FROM unnest(COALESCE(identities.tags,
                                                         ARRAY[]::text[])
                                                || EXCLUDED.tags) t)
                RETURNING (xmax = 0) AS inserted
            """, (p["provider"], p["identifier"], p["display_name"], p["host"],
                  p["sources"], p["tags"],
                  Json({"host": p["host"], "discovered_by": p["sources"],
                        "discovery": "smb_rpc_enumeration"})))
            got = cur.fetchone()
            if got is not None:
                was_new = got["inserted"] if isinstance(got, dict) else got[0]
                inserted += 1 if was_new else 0
                updated += 0 if was_new else 1
        cur.connection.commit()

    return {"executions_read": len(rows), "found": len(planned),
            "inserted": inserted, "updated": updated, "dry_run": dry_run,
            "hosts": sorted({p["host"] for p in planned}),
            "sample": planned[:15]}
