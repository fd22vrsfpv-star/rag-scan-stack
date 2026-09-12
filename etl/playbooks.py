"""The methodology playbooks, as something other than prose.

WHY THIS EXISTS
---------------
`knowledge/playbooks/*.md` holds 3,896 lines of real methodology across twelve
services and techniques. All of it was RAG context: a language model could be
told about a step, but nothing could enumerate the steps for a host, nothing
could run one, and nothing recorded whether any had been done.

The concrete cost: `ssh_methodology.md` has a "Post-Exploitation / If Access
Gained" checklist — sudo rights, authorized_keys, known_hosts, sshd_config, key
reuse — that no code path could reach. A run that recovered a working SSH
credential did none of it, and the report could not say which parts were skipped.

`scripts/playbooks_to_yaml.py` extracts the structure into
`knowledge/playbooks/*.yaml`. This module is the read side: pick the playbook for
a service, filter the steps by what access you actually have, and render their
commands against a target.

SELECTION IS NOT AUTHORISATION
------------------------------
`steps_for()` answers "what does the methodology say to do here". It never
decides that something may run. Anything a caller dispatches from these steps
goes through the scope gate and its phase's approval exactly like every other
dispatch, and `access_required` is a FILTER so a recon consumer is not handed
post-exploitation commands — not a permission.

THE MARKDOWN STAYS AUTHORITATIVE
--------------------------------
The YAML is an extract, regenerated from the prose. `tests/test_playbooks.py`
fails if they drift, so a command here can never be one the methodology does not
contain.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Iterable, List, Optional

log = logging.getLogger("playbooks")

DIRS = [
    os.environ.get("PLAYBOOKS_DIR", "/knowledge/playbooks"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "knowledge", "playbooks"),
]

# What a step needs before it is worth proposing. Ordered weakest to strongest,
# so a caller says "I have a credential" and gets everything at or below that.
ACCESS_LEVELS = ("none", "credential", "shell")

# Which playbook covers which service. A service with no playbook returns
# nothing rather than guessing: a plausible-looking step from the wrong
# methodology is worse than no step, because the operator has no reason to doubt
# it. Names are the YAML `name`, i.e. the markdown filename without .md.
SERVICE_PLAYBOOKS: Dict[str, List[str]] = {
    "ssh": ["ssh_methodology"],
    "smb": ["smb_methodology", "lateral_movement", "credential_dumping"],
    "microsoft-ds": ["smb_methodology"],
    "netbios-ssn": ["smb_methodology"],
    "http": ["web_methodology"],
    "https": ["web_methodology"],
    "mysql": ["database_methodology"],
    "postgresql": ["database_methodology"],
    "postgres": ["database_methodology"],
    "mssql": ["database_methodology"],
    "oracle": ["database_methodology"],
    "mongodb": ["database_methodology"],
    "redis": ["database_methodology"],
    "ftp": ["network_services"],
    "telnet": ["network_services"],
    "smtp": ["network_services"],
    "snmp": ["network_services"],
    "rdp": ["lateral_movement", "network_services"],
    "ldap": ["active_directory_attacks"],
    "kerberos": ["active_directory_attacks"],
    "vnc": ["network_services"],
}

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_]+)\}")
_cache: Dict[str, Dict[str, Any]] = {}


def _dir() -> Optional[str]:
    for d in DIRS:
        if d and os.path.isdir(d):
            return d
    return None


def load(name: str) -> Dict[str, Any]:
    """One playbook by name, or `{}` if it cannot be read.

    Empty is a real answer and is logged: no playbook means no steps, which is
    the safe direction. It never raises — a missing knowledge mount must not
    fail whatever was calling.
    """
    if name in _cache:
        return _cache[name]
    base = _dir()
    if not base:
        log.warning("no playbook directory found (looked in %s)", DIRS)
        return {}
    path = os.path.join(base, f"{name}.yaml")
    if not os.path.exists(path):
        return {}
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except Exception as e:  # noqa: BLE001
        log.warning("playbook %s unreadable: %s", path, e)
        return {}
    _cache[name] = doc
    return doc


def available() -> List[str]:
    """Playbook names present on disk, including ones with no usable steps."""
    base = _dir()
    if not base:
        return []
    return sorted(f[:-5] for f in os.listdir(base) if f.endswith(".yaml"))


def playbooks_for(service: str) -> List[str]:
    """Which playbooks cover this service. Empty when none do — deliberately."""
    return SERVICE_PLAYBOOKS.get((service or "").strip().lower(), [])


def steps_for(service: str = "", *, playbook: Optional[str] = None,
              access: str = "none", phase: Optional[str] = None,
              include_commandless: bool = False,
              include_mutating: bool = False) -> List[Dict[str, Any]]:
    """The methodology steps that apply, as a flat list.

    `access` is what the caller HAS — `none`, `credential` or `shell` — and
    steps needing more than that are filtered out. That is the point of the
    field: a recon consumer must not be handed post-exploitation commands, and
    a consumer holding a working credential should not have to re-derive which
    half of the playbook it just unlocked.

    **Mutating steps are excluded by default.** The methodology legitimately
    documents persistence and evasion — 45 of the 266 steps write to the target,
    `useradd backdoor` and `>> authorized_keys` among them. This platform
    collects data for a tester to act on, so anything that queues steps
    automatically must opt IN to changing a host, explicitly and visibly. A
    caller that wants them asks for them.

    Steps with no commands are dropped unless asked for: they are section
    headers and prose in the markdown, useful to read and not to act on.
    """
    if access not in ACCESS_LEVELS:
        raise ValueError(f"access must be one of {ACCESS_LEVELS}, got {access!r}")
    ceiling = ACCESS_LEVELS.index(access)

    names = [playbook] if playbook else playbooks_for(service)
    out: List[Dict[str, Any]] = []
    for name in names:
        doc = load(name)
        for ph in doc.get("phases") or []:
            if phase and ph.get("id") != phase and ph.get("name") != phase:
                continue
            for st in ph.get("steps") or []:
                need = st.get("access_required") or "none"
                if need not in ACCESS_LEVELS or ACCESS_LEVELS.index(need) > ceiling:
                    continue
                if st.get("mutates") and not include_mutating:
                    continue
                cmds = st.get("commands") or []
                if not cmds and not include_commandless:
                    continue
                out.append({
                    "playbook": name,
                    "phase": ph.get("name"),
                    "phase_id": ph.get("id"),
                    "id": st.get("id"),
                    "title": st.get("title"),
                    "access_required": need,
                    "mutates": bool(st.get("mutates")),
                    "commands": cmds,
                    "checks": st.get("checks") or [],
                    "source": f"{doc.get('source')}:{st.get('source_line')}",
                })
    return out


def render(command: str, **values: Any) -> Dict[str, Any]:
    """Substitute `{target}` etc. and report what could not be filled.

    ``{"command", "unresolved"}``. Unresolved placeholders are RETURNED, not
    silently left in: a command dispatched with a literal `{target}` fails with
    an error that looks like a tool problem, and the cause is already known here.
    """
    out = command or ""
    for key, value in (values or {}).items():
        if value is None:
            continue
        out = out.replace("{" + key + "}", str(value))
    return {"command": out, "unresolved": sorted(set(_PLACEHOLDER.findall(out)))}


def checklist(service: str = "", *, access: str = "shell",
              playbook: Optional[str] = None, include_mutating: bool = False,
              **values: Any) -> List[Dict[str, Any]]:
    """Steps rendered against a target — the operator-facing list of what to check.

    This is the answer to "what is the post-enumeration list for this host": the
    methodology's own steps, with the target filled in, each carrying what it is
    for and where in the playbook it came from.
    """
    items = []
    for st in steps_for(service, playbook=playbook, access=access,
                        include_mutating=include_mutating):
        rendered = []
        for c in st["commands"]:
            r = render(c.get("command", ""), **values)
            rendered.append({"lang": c.get("lang"), **r})
        items.append({**st, "commands": rendered,
                      "runnable": all(not r["unresolved"] for r in rendered)})
    return items


def coverage(service: str = "", *, done_ids: Iterable[str] = (),
             access: str = "shell") -> Dict[str, Any]:
    """How much of the methodology has actually been done.

    Nothing could answer this before, because nothing could enumerate the steps.
    A report that cannot say what was skipped is not a report of coverage.
    """
    steps = steps_for(service, access=access)
    done = set(done_ids or ())
    covered = [s for s in steps if s["id"] in done]
    return {
        "service": service,
        "total": len(steps),
        "done": len(covered),
        "remaining": [
            {"id": s["id"], "title": s["title"], "phase": s["phase"],
             "playbook": s["playbook"]}
            for s in steps if s["id"] not in done
        ],
    }
