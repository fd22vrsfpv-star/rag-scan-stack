"""Discovered values that influence how a host is tested.

WHY THIS EXISTS
---------------
Four tools already produce parameter-shaped facts, each in its own shape:

    netexec    smb_password_policy   params.lockout_threshold
    ssh-audit  ssh_config            banner, software, algorithms[]
    wafw00f    waf_detection         detected, firewall
    httpx      web_service           webserver, tech[]

Nothing could read them generically, so nothing did — while two of them predict
whether a scan can work at all:

* `Account Lockout Threshold: None` is what makes a 4,100-candidate spray safe
  here. With a threshold of 3 the same list is an account-lockout denial of
  service across every account in the userlist.
* OpenSSH 4.7p1 offers only legacy MACs and modern hydra offers only SHA2, so
  `hydra ssh://` cannot negotiate with this host at all — every SSH brute-force
  proposal against it is dead on arrival.

THREE LAYERS, one of them stored
--------------------------------
    observed   read from findings and executions, WITH provenance. Never copied
               into a table: a copy goes stale the moment a re-scan disagrees.
    declared   `scan_parameters`, operator-only. No tool can discover
               "never spray this host".
    effective  declared -> observed -> the default in the vocabulary.

The vocabulary and its source mappings live in knowledge/scan_parameters.yaml —
a read-only bind mount, so keys can be added without a rebuild.
"""
import os
import re
from typing import Any, Dict, List, Optional

VOCAB_FILE = os.environ.get("SCAN_PARAMETERS_FILE",
                            "/knowledge/scan_parameters.yaml")

_cache: Dict[str, Any] = {"mtime": None, "vocab": {}}


def load_vocabulary(path: str = None) -> Dict[str, Any]:
    """{key: declaration}. Returns {} rather than raising on a bad file."""
    path = path or VOCAB_FILE
    try:
        import yaml
    except ImportError:
        return {}
    try:
        stamp = os.path.getmtime(path)
    except OSError:
        return {}
    if _cache["mtime"] == stamp and _cache["vocab"]:
        return _cache["vocab"]
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except Exception:                       # noqa: BLE001
        return {}
    vocab = doc.get("parameters") or {}
    _cache.update({"mtime": stamp, "vocab": vocab})
    return vocab


def _dig(payload, path: str):
    """Follow a dotted path into nested dicts. None when any step is missing."""
    cur = payload
    for part in (path or "").split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _observe_from_findings(cur, host: str, spec: dict, source: dict):
    """Read a value out of recon_findings, newest first."""
    cur.execute("""
        SELECT source, data, created_at
          FROM recon_findings
         WHERE finding_type = %s AND target = %s
         ORDER BY created_at DESC
         LIMIT 25
    """, (source.get("finding_type"), host))
    for row in cur.fetchall():
        src = row["source"] if isinstance(row, dict) else row[0]
        data = row["data"] if isinstance(row, dict) else row[1]
        seen = row["created_at"] if isinstance(row, dict) else row[2]
        value = _dig(data, source.get("path", ""))
        if value is not None:
            return {"value": value, "tool": src,
                    "observed_at": seen.isoformat() if seen else None,
                    "via": f"recon_findings.{source.get('finding_type')}"
                           f".{source.get('path')}"}
    return None


def _observe_from_executions(cur, host: str, spec: dict, source: dict):
    """Read a value out of stored tool output by regex.

    `aggregate: min` is the honest default for a RATE. Measured hydra rates on
    this engagement were 16, 22, 116 and 256 tries/min — the guard hardcoded
    256, the best case, so its time estimate was optimistic by up to 16x.
    """
    cur.execute("""
        SELECT tool, COALESCE(output, '') AS output, started_at
          FROM tool_executions
         WHERE target = %s AND tool = %s
           AND octet_length(COALESCE(output, '')) > 0
         ORDER BY started_at DESC
         LIMIT 100
    """, (host, source.get("tool")))
    try:
        # MULTILINE, like extractor_specs.run_deterministic. Tool output is
        # line-oriented and these patterns are line-anchored: without re.M a
        # `^` only matches the start of the whole blob, so `^\(mac\)` found 0
        # of the 7 MAC lines and the parameter silently fell back to its default.
        rx = re.compile(source.get("pattern", ""), re.M)
    except re.error:
        return None
    as_list = spec.get("type") == "list"
    values, tool, when = [], None, None
    for row in cur.fetchall():
        output = row["output"] if isinstance(row, dict) else row[1]
        for m in rx.findall(output):
            text = m if isinstance(m, str) else (m[0] if m else "")
            if as_list:
                if text.strip():
                    values.append(text.strip())
                continue
            try:
                values.append(float(text))
            except (TypeError, ValueError):
                continue
        if values and tool is None:
            tool = row["tool"] if isinstance(row, dict) else row[0]
            when = row["started_at"] if isinstance(row, dict) else row[2]
    if not values:
        return None
    how = (spec.get("aggregate") or "max").lower()
    if spec.get("type") == "list":
        # Distinct, order preserved. An algorithm list is a SET of capabilities,
        # not something to aggregate to one number.
        seen, uniq = set(), []
        for v in values:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        return {"value": uniq, "tool": tool,
                "observed_at": when.isoformat() if when else None,
                "via": f"tool_executions[{source.get('tool')}] "
                       f"{len(uniq)} distinct match(es)"}
    picked = {"min": min, "max": max}.get(how, max)(values)
    return {"value": picked, "tool": tool,
            "observed_at": when.isoformat() if when else None,
            "via": f"tool_executions[{source.get('tool')}] {how} of "
                   f"{len(values)} sample(s)"}


def observed(cur, host: str, keys: List[str] = None,
             vocab_path: str = None) -> Dict[str, dict]:
    """Values read from evidence, each carrying where it came from."""
    vocab = load_vocabulary(vocab_path)
    out = {}
    for key, spec in vocab.items():
        if keys and key not in keys:
            continue
        for source in spec.get("sources") or []:
            kind = source.get("kind")
            got = None
            if kind == "finding":
                got = _observe_from_findings(cur, host, spec, source)
            elif kind == "execution_regex":
                got = _observe_from_executions(cur, host, spec, source)
            if got is not None:
                out[key] = got
                break
    return out


def declared(cur, host: str, keys: List[str] = None) -> Dict[str, dict]:
    """Operator statements. Host scope wins over global."""
    cur.execute("""
        SELECT key, value, note, declared_by, scope_type, updated_at
          FROM scan_parameters
         WHERE (scope_type = 'host' AND scope_value = %s)
            OR scope_type = 'global'
         ORDER BY CASE scope_type WHEN 'host' THEN 0 ELSE 1 END
    """, (host,))
    out = {}
    for row in cur.fetchall():
        r = dict(row) if isinstance(row, dict) else {
            "key": row[0], "value": row[1], "note": row[2],
            "declared_by": row[3], "scope_type": row[4], "updated_at": row[5]}
        if keys and r["key"] not in keys:
            continue
        if r["key"] in out:
            continue        # host scope already won
        out[r["key"]] = {"value": r["value"], "note": r.get("note"),
                         "declared_by": r.get("declared_by"),
                         "scope": r["scope_type"],
                         "updated_at": r["updated_at"].isoformat()
                         if r.get("updated_at") else None}
    return out


def effective(cur, host: str, keys: List[str] = None,
              vocab_path: str = None) -> Dict[str, dict]:
    """What a scan should actually use, and WHY it has that value.

    `provenance` is always reported. A consumer that cannot tell a measured
    value from a default will treat "we never checked" as "no lockout", which is
    the failure this whole layer exists to prevent.
    """
    vocab = load_vocabulary(vocab_path)
    obs = observed(cur, host, keys, vocab_path)
    dec = declared(cur, host, keys)
    out = {}
    for key, spec in vocab.items():
        if keys and key not in keys:
            continue
        if key in dec:
            out[key] = {**dec[key], "provenance": "declared",
                        "influences": spec.get("influences") or [],
                        "observed": obs.get(key)}
        elif key in obs:
            out[key] = {**obs[key], "provenance": "observed",
                        "influences": spec.get("influences") or []}
        else:
            out[key] = {"value": spec.get("default"), "provenance": "default",
                        "influences": spec.get("influences") or [],
                        "note": "never observed on this host"}
        out[key]["description"] = spec.get("description")
        out[key]["why"] = spec.get("why")
    return out


# ── consumers ───────────────────────────────────────────────────────────────
#
# A parameter is only worth storing when something reads it. These are small and
# specific on purpose: a generic "apply parameters to scans" engine would be one
# that applies none.

# hydra's client-side MAC list, taken from the error it produced against this
# host — measured, not assumed:
#
#   kex error : no match for method mac algo client->server:
#     server [hmac-md5, hmac-sha1, umac-64@openssh.com, hmac-ripemd160,
#             hmac-ripemd160@openssh.com, hmac-sha1-96, hmac-md5-96],
#     client [hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com,
#             hmac-sha2-256, hmac-sha2-512]
#
# This varies with the libssh build hydra was compiled against, which is why an
# EMPTY server list means "we do not know" and nothing is withheld. Suppressing
# work we cannot prove is futile would be the worse error: a withheld scan that
# would have worked is invisible, while a failed one at least shows up.
HYDRA_SSH_CLIENT_MACS = {
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512",
}

# HYDRA ONLY, and that restriction is itself measured.
#
# The first version of this check also covered medusa and ncrack on the
# assumption that they share hydra's crypto constraints. They do not — medusa
# against the SAME host completed a full ACCOUNT CHECK where hydra died at key
# exchange:
#
#   medusa -h 192.168.1.150 -U u -P p -M ssh
#   ACCOUNT CHECK: [ssh] Host: 192.168.1.150 User: root Password: x   (exit 0)
#
# So medusa is the working SSH tool on legacy-MAC hosts, and withholding it
# would have suppressed the one thing that does work. Add a tool here only after
# measuring it fail.
_SSH_BRUTE_TOOLS = {"hydra"}

# Measured to negotiate successfully with legacy-MAC servers, so it is worth
# naming in the refusal rather than leaving the operator with nothing.
_SSH_FALLBACK_TOOL = "medusa"


def ssh_brute_force_viable(cur, host: str, tool: str, command: str,
                           vocab_path: str = None):
    """None when an SSH credential attack can proceed, else why it cannot.

    hydra could not negotiate SSH with this host AT ALL — the server offers only
    legacy MACs and modern hydra offers only SHA2 ones. Every SSH brute-force
    proposal against it was therefore dead on arrival, and would have been
    recorded as a scan that found nothing: indistinguishable from a host with
    strong passwords.

    Only claims futility when BOTH lists are known and disjoint.
    """
    if (tool or "").strip().lower() not in _SSH_BRUTE_TOOLS:
        return None
    text = (command or "").lower()
    if "ssh://" not in text and "-m ssh" not in text and " ssh " not in text:
        return None
    try:
        v = effective(cur, host, ["ssh_mac_algorithms"], vocab_path)
        server = v.get("ssh_mac_algorithms") or {}
    except Exception:                       # noqa: BLE001
        return None
    macs = server.get("value") or []
    if not macs or server.get("provenance") == "default":
        return None                          # never measured: do not suppress
    if set(macs) & HYDRA_SSH_CLIENT_MACS:
        return None                          # a shared MAC exists; it can connect
    return (f"{tool} cannot negotiate SSH with {host}: the server offers only "
            f"{', '.join(sorted(macs)[:4])}"
            + (" ..." if len(macs) > 4 else "")
            + f" and {tool} requires one of "
              f"{', '.join(sorted(HYDRA_SSH_CLIENT_MACS)[:2])} ... — the run "
              f"would fail at key exchange and be recorded as finding nothing. "
              f"Use {_SSH_FALLBACK_TOOL}, which was measured to negotiate with "
              f"this server.")
