"""The access the platform actually holds, measured and ranked.

WHY THIS EXISTS
---------------
Exploits ran and shells were obtained, and the platform had no concept of
either. The vsftpd backdoor opened a root shell on port 6200; the row in
`pending_exploits` said `executed` and nothing recorded that access existed,
what privilege it had, or whether it still worked.

With one exploit that was a gap. Now that the planner queues every
well-evidenced candidate, several succeed and each leaves something behind —
and running the post-enumeration checklist through all of them would be slow and
pointless. The checklist wants ONE shell: the highest privilege that is actually
stable.

MEASURED, NOT ASSUMED
---------------------
`id` says the privilege. Repeated probes say whether it holds. A root shell that
dies on the second command is worse than a user shell that answers every time,
and only asking more than once tells them apart — which is why `probes` and
`probes_ok` are counted separately and why the score is recomputed on every
probe rather than set when the access is discovered.

NOT ONLY METASPLOIT
-------------------
A session is anything a command can be run through. Metasploit is one transport;
a bind shell on a port an exploit opened, an SSH credential, and a reverse shell
caught by the Kali listener are others, and the ranking treats them the same way
because the question — what privilege, does it hold — is the same question.

Adding a transport is one entry in `TRANSPORTS` plus a runner function. There is
deliberately no fallback "just try netcat": a transport nobody wrote a runner
for reports as unusable rather than silently doing something else.

AUTHORISATION IS UNCHANGED
--------------------------
This runs commands through access that ALREADY EXISTS, obtained by an exploit an
operator approved or a credential already discovered. It opens nothing, and the
scope gate still applies to every dispatch that reaches a target.
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("access")

DB_DSN = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL") or \
    "postgresql://app:app@rag-postgres:5432/scans"
EXPLOIT_RUNNER_URL = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8021")
KALI_LISTENER_URL = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")

# How long a single probe may take. A shell that cannot answer `id` in this long
# is not one the checklist should be run through, whatever its privilege.
PROBE_TIMEOUT = int(os.environ.get("ACCESS_PROBE_TIMEOUT", "20"))

# How many times to ask before trusting it. One answer proves it replied once;
# the whole point of "stable" is that it keeps replying.
STABILITY_PROBES = int(os.environ.get("ACCESS_STABILITY_PROBES", "3"))

_UID_RE = re.compile(r"uid=(\d+)")
_WHOAMI_RE = re.compile(r"uid=\d+\(([^)]+)\)")


def _connect():
    import psycopg2
    return psycopg2.connect(DB_DSN, connect_timeout=5)


# ── Transports ─────────────────────────────────────────────────────────────
#
# Each runs ONE command through one kind of access and returns its output, or
# raises. Metasploit is one of four, not the assumption.

def _run_msf(handle: str, command: str, **_) -> str:
    import requests
    r = requests.post(
        f"{EXPLOIT_RUNNER_URL.rstrip('/')}/msf/sessions/{handle}/command",
        json={"command": command}, timeout=PROBE_TIMEOUT,
        headers={"x-api-key": os.environ.get("API_KEY", "")},
        verify=os.environ.get("REQUESTS_CA_BUNDLE", False))
    r.raise_for_status()
    return (r.json() or {}).get("output") or ""


def _run_bind_shell(handle: str, command: str, **_) -> str:
    """A raw listener an exploit opened — the vsftpd backdoor's port 6200.

    Not a Metasploit session and never will be: the exploit opened a socket and
    walked away. It is still a root shell and still the best access on the host,
    so it has to be reachable or the ranking is a ranking of the wrong things.
    """
    host, _, port = handle.partition(":")
    if not (host and port):
        raise ValueError(f"bind shell handle {handle!r} is not host:port")
    # Piped, not interactive. `nc` closes on EOF, which is what makes a bind
    # shell usable non-interactively at all.
    proc = subprocess.run(
        ["nc", "-w", str(min(PROBE_TIMEOUT, 15)), host, port],
        input=f"{command}\nexit\n", capture_output=True, text=True,
        timeout=PROBE_TIMEOUT)
    return (proc.stdout or "") + (proc.stderr or "")


def _run_ssh_credential(handle: str, command: str, **kw) -> str:
    """An SSH credential is access too, and often the most stable kind.

    The algorithm options come from what recon measured about the host —
    without them ssh will not negotiate with a legacy server at all.
    """
    target = kw.get("target") or ""
    port = kw.get("port") or 22
    username, _, password = handle.partition(":")
    opts = ["-oStrictHostKeyChecking=no", "-oConnectTimeout=10", "-oBatchMode=no"]
    try:
        from etl.target_capabilities import settings_for
        opts = list(settings_for("ssh", target, port=port)) + opts
    except Exception:  # noqa: BLE001
        pass
    env = dict(os.environ, SSHPASS=password)
    proc = subprocess.run(
        ["sshpass", "-e", "ssh", *opts, "-p", str(port),
         f"{username}@{target}", command],
        capture_output=True, text=True, timeout=PROBE_TIMEOUT, env=env)
    return (proc.stdout or "") + (proc.stderr or "")


def _run_listener_callback(handle: str, command: str, **_) -> str:
    """A reverse shell caught by the Kali listener."""
    import requests
    r = requests.post(
        f"{KALI_LISTENER_URL.rstrip('/')}/callbacks/{handle}/command",
        json={"command": command}, timeout=PROBE_TIMEOUT,
        headers={"x-api-key": os.environ.get("API_KEY", "")},
        verify=os.environ.get("REQUESTS_CA_BUNDLE", False))
    r.raise_for_status()
    return (r.json() or {}).get("output") or ""


TRANSPORTS: Dict[str, Callable[..., str]] = {
    "msf_session": _run_msf,
    "bind_shell": _run_bind_shell,
    "ssh_credential": _run_ssh_credential,
    "listener_callback": _run_listener_callback,
}


def run(access: Dict[str, Any], command: str) -> Dict[str, Any]:
    """Run one command through one access. Never raises.

    ``{"ok", "output", "error"}``. A transport with no runner reports
    `unsupported transport` rather than falling back to something else — a
    silent fallback would mean the operator believes a command ran through the
    access they chose when it ran through a different one.
    """
    fn = TRANSPORTS.get(access.get("kind") or "")
    if not fn:
        return {"ok": False, "output": "",
                "error": f"unsupported transport: {access.get('kind')!r}"}
    try:
        out = fn(access.get("handle") or "", command,
                 target=access.get("target"), port=access.get("port"))
        return {"ok": True, "output": out or "", "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "output": "", "error": f"{type(e).__name__}: {e}"[:300]}


# ── Ranking ────────────────────────────────────────────────────────────────

def score_for(is_root: Optional[bool], probes: int, probes_ok: int,
              kind: str = "") -> int:
    """Privilege dominates; stability breaks ties and demotes a flaky root.

    A root shell that answers one probe in three scores below a user shell that
    answers all three, because the checklist is a sequence of commands and a
    shell that drops halfway through produces a half-finished enumeration that
    looks like a complete one.
    """
    if probes and not probes_ok:
        return 0                       # answered nothing; it is not access
    base = 100 if is_root else (40 if is_root is False else 10)
    reliability = (probes_ok / probes) if probes else 0.0
    # Interactive transports keep state between commands; a piped bind shell
    # starts fresh each time. A small preference, never enough to outrank
    # privilege.
    bonus = {"msf_session": 5, "listener_callback": 4,
             "ssh_credential": 3, "bind_shell": 0}.get(kind, 0)
    return int(base * reliability) + bonus


def probe(access: Dict[str, Any], *, rounds: int = None) -> Dict[str, Any]:
    """Ask an access who it is, more than once.

    Returns the updated fields. `whoami`/`is_root` stay None when nothing
    answered — "not probed" and "unprivileged" are different, and recording the
    first as the second would rank a dead root shell as a live user one.
    """
    rounds = STABILITY_PROBES if rounds is None else rounds
    ok = 0
    whoami = uid = os_info = None
    last_error = ""
    for _ in range(max(1, rounds)):
        res = run(access, "id; uname -a")
        if not res["ok"]:
            last_error = res["error"]
            continue
        text = res["output"]
        m = _UID_RE.search(text)
        if not m:
            # It answered, but not with anything recognisable. That is a
            # responding channel with unknown privilege, not a failure.
            last_error = "no uid in response"
            ok += 1
            continue
        ok += 1
        uid = int(m.group(1))
        w = _WHOAMI_RE.search(text)
        whoami = w.group(1) if w else None
        for line in text.splitlines():
            if line.lower().startswith("linux") or " gnu/linux" in line.lower():
                os_info = line.strip()[:200]
                break
    is_root = None if uid is None else (uid == 0)
    return {
        "whoami": whoami, "uid": uid, "is_root": is_root, "os_info": os_info,
        "probes": max(1, rounds), "probes_ok": ok,
        "last_error": last_error[:300] or None,
        "status": "live" if ok else "dead",
        "score": score_for(is_root, max(1, rounds), ok, access.get("kind") or ""),
    }


# ── Discovery ──────────────────────────────────────────────────────────────

def discover(target: str, *, cur=None) -> List[Dict[str, Any]]:
    """Every access we might hold on this target, from every source.

    Candidates only — nothing here is verified. `probe()` decides what is real,
    which is the point: a bind shell on a port an exploit opened and a
    Metasploit session are equally plausible until one of them answers `id`.
    """
    found: List[Dict[str, Any]] = []

    # 1. Metasploit sessions. One transport among several, not the assumption.
    try:
        import requests
        r = requests.get(f"{EXPLOIT_RUNNER_URL.rstrip('/')}/msf/sessions",
                         timeout=10,
                         headers={"x-api-key": os.environ.get("API_KEY", "")},
                         verify=os.environ.get("REQUESTS_CA_BUNDLE", False))
        if r.status_code == 200:
            for sess in (r.json() or {}).get("sessions") or []:
                peer = str(sess.get("tunnel_peer") or "")
                if target and target not in peer and target not in str(sess.get("desc") or ""):
                    continue
                found.append({"target": target, "port": None,
                              "kind": "msf_session",
                              "handle": str(sess.get("session_id")),
                              "transport": str(sess.get("type") or "shell")})
    except Exception as e:  # noqa: BLE001
        log.debug("msf session discovery failed: %s", e)

    own = cur is None
    conn = None
    try:
        if own:
            conn = _connect()
            cur = conn.cursor()

        # 2. Bind shells: a port an exploit opened that nothing has identified.
        #    This is where the vsftpd backdoor lands — a socket, no session.
        try:
            from etl.post_enumeration import facts_from_open_ports
            for f in facts_from_open_ports(cur, target=target):
                found.append({"target": f["target"], "port": f["port"],
                              "kind": "bind_shell",
                              "handle": f"{f['target']}:{f['port']}",
                              "transport": "raw"})
        except Exception as e:  # noqa: BLE001
            log.debug("bind shell discovery failed: %s", e)

        # 3. Credentials. Often the most stable access on a host, and the one
        #    that survives a reboot.
        try:
            cur.execute(
                """SELECT username, secret_value, port FROM credential_findings
                    WHERE host(ip) = %s AND valid_cred = true
                      AND protocol = 'ssh' AND secret_value IS NOT NULL
                    ORDER BY created_at DESC LIMIT 5""", (target,))
            for username, secret, port in cur.fetchall():
                found.append({"target": target, "port": port or 22,
                              "kind": "ssh_credential",
                              "handle": f"{username}:{secret}",
                              "transport": "ssh"})
        except Exception as e:  # noqa: BLE001
            log.debug("credential discovery failed: %s", e)
    finally:
        if own and conn is not None:
            conn.close()
    return found


def refresh(target: str, *, rounds: int = None,
            engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """Discover, probe and record every access on this target.

    Returns a summary with the ranking. Probing costs a few commands per
    candidate, which is the price of not running the whole post-enumeration
    checklist through a shell that was never going to answer.
    """
    out = {"target": target, "discovered": 0, "live": 0, "dead": 0,
           "best": None, "ranked": [], "available": False}
    candidates = discover(target)
    out["discovered"] = len(candidates)
    if not candidates:
        return out
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                for cand in candidates:
                    result = probe(cand, rounds=rounds)
                    cur.execute(
                        """
                        INSERT INTO public.obtained_access
                          (target, port, kind, handle, transport, whoami, uid,
                           is_root, os_info, probes, probes_ok, last_probe_at,
                           last_error, score, status, engagement_id)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),%s,%s,%s,%s)
                        ON CONFLICT (target, kind, handle) DO UPDATE SET
                          whoami = EXCLUDED.whoami, uid = EXCLUDED.uid,
                          is_root = EXCLUDED.is_root, os_info = EXCLUDED.os_info,
                          probes = public.obtained_access.probes + EXCLUDED.probes,
                          probes_ok = public.obtained_access.probes_ok
                                      + EXCLUDED.probes_ok,
                          last_probe_at = now(), last_error = EXCLUDED.last_error,
                          score = EXCLUDED.score,
                          -- A rejected access stays rejected: an operator who
                          -- ruled one out is not overruled by it answering.
                          status = CASE
                              WHEN public.obtained_access.status = 'rejected'
                                   THEN 'rejected' ELSE EXCLUDED.status END
                        """,
                        (cand["target"], cand.get("port"), cand["kind"],
                         cand["handle"], cand.get("transport", ""),
                         result["whoami"], result["uid"], result["is_root"],
                         result["os_info"], result["probes"], result["probes_ok"],
                         result["last_error"], result["score"], result["status"],
                         engagement_id))
                    if result["status"] == "live":
                        out["live"] += 1
                    else:
                        out["dead"] += 1
                    out["ranked"].append({
                        "kind": cand["kind"], "handle": cand["handle"],
                        "whoami": result["whoami"], "is_root": result["is_root"],
                        "probes": f"{result['probes_ok']}/{result['probes']}",
                        "score": result["score"]})
            conn.commit()
        out["available"] = True
    except Exception as e:  # noqa: BLE001
        log.warning("access refresh failed for %s: %s", target, e)
        return out
    out["ranked"].sort(key=lambda a: -a["score"])
    out["best"] = out["ranked"][0] if out["ranked"] and out["ranked"][0]["score"] else None
    return out


def best_for(target: str) -> Optional[Dict[str, Any]]:
    """The access the post-enumeration checklist should run through.

    One shell, chosen by measurement. Running the checklist through every shell
    would be slow, noisy on the target, and would produce several partial
    answers to the same question instead of one complete one.
    """
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT id::text, target, port, kind, handle, transport,
                          whoami, is_root, score, probes, probes_ok
                     FROM public.obtained_access
                    WHERE target = %s AND status = 'live' AND score > 0
                    ORDER BY score DESC, probes_ok DESC
                    LIMIT 1""", (target,))
            row = cur.fetchone()
    except Exception as e:  # noqa: BLE001
        log.debug("best_for failed: %s", e)
        return None
    if not row:
        return None
    keys = ("id", "target", "port", "kind", "handle", "transport", "whoami",
            "is_root", "score", "probes", "probes_ok")
    return dict(zip(keys, row))
