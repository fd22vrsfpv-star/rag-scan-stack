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
        rx = re.compile(source.get("pattern", ""))
    except re.error:
        return None
    values, tool, when = [], None, None
    for row in cur.fetchall():
        output = row["output"] if isinstance(row, dict) else row[1]
        for m in rx.findall(output):
            try:
                values.append(float(m if isinstance(m, str) else m[0]))
            except (TypeError, ValueError):
                continue
        if values and tool is None:
            tool = row["tool"] if isinstance(row, dict) else row[0]
            when = row["started_at"] if isinstance(row, dict) else row[2]
    if not values:
        return None
    how = (spec.get("aggregate") or "max").lower()
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
