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
_NOT_USERNAMES = {
    "username", "user", "name", "account", "login", "password", "share",
    "permissions", "remark", "null", "none", "true", "false", "unknown",
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
    found: Dict[str, List[str]] = {"vault": [], "findings": [], "extracted": []}

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
    for key in ("findings", "vault", "extracted"):
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

    return {
        "target": target, "port": port, "service": svc,
        "users": users, "passwords": passwords,
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
