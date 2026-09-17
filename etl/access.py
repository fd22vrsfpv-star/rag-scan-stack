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
# Non-shell service access: a prober that authenticated returns this instead of
# `uid=`. AUTH_OK means logged in (optionally naming the user); REACHABLE means
# the service answered but auth was not proven.
_AUTH_RE = re.compile(r"\bAUTH_OK\b(?:\s+user=(?P<user>\S+))?")
_PRIV_RE = re.compile(r"\bpriv=1\b")
_REACH_RE = re.compile(r"\bREACHABLE\b")
# A crypt/shadow hash ($1$ md5, $5$/$6$ sha, $2y$ bcrypt, $y$ yescrypt …) is a
# CRACK target, not a login. Offering it as a password just probes dead; the
# cracked plaintext returns later as a real 'password' credential.
_CRYPT_HASH_RE = re.compile(r"^\$(?:1|2[aby]?|5|6|7|y|gy|md5|sha1|sha256|sha512)\$", re.I)


def _is_crypt_hash(secret) -> bool:
    return bool(secret and _CRYPT_HASH_RE.match(str(secret).strip()))


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
    # The shell's reply is STDOUT. nc writes its OWN diagnostics to STDERR —
    # "Connection refused", "forward host lookup failed" — which are nc
    # explaining why there is no shell, not the shell answering. Merging them
    # counted a refused port's "Connection refused" as a non-empty reply with no
    # uid, scoring a UDP-only / closed port 10 ("answered, unknown privilege")
    # and ranking it ABOVE a genuinely-open silent port. Same reasoning as the
    # ssh transport: stderr alone is not output. So the reply is stdout only.
    out = proc.stdout or ""
    # A connection that never connected is NOT an answer. subprocess.run does not
    # raise on a non-zero exit, so without this a refused or black-holed port
    # returned "" and was recorded as a shell that replied. Now that stderr is
    # excluded, an empty stdout on a non-zero exit is exactly that case.
    if proc.returncode != 0 and not out.strip():
        why = (proc.stderr or "").strip().splitlines()
        raise ConnectionError(
            f"nc exited {proc.returncode} from {host}:{port}"
            + (f": {why[-1][:120]}" if why else " with no output"))
    return out


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
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0 and not (proc.stdout or "").strip():
        # stderr alone is ssh explaining why it could not log in, not output.
        raise ConnectionError(
            f"ssh exited {proc.returncode}: {out.strip()[:160] or 'no output'}")
    return out


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


def _run_webshell(handle: str, command: str, **_) -> str:
    """A web shell an exploit planted — the invocation URL carries a `{cmd}` slot.

    Not a session and not a socket: each command is one HTTP GET that runs
    through the PHP shell dropped on the target and returns its stdout as the
    body. Stateless (a fresh process per request, like a piped bind shell), but
    it is real held access and survives as long as the file is on disk — which
    is why it belongs in obtained_access, ranked next to bind/ssh/msf. Mirrors
    the invocation exploit-runner already uses for post-ex (`{cmd}` → url-quoted).
    """
    import urllib.parse
    import requests
    if "{cmd}" not in handle:
        raise ValueError(f"webshell handle {handle!r} has no {{cmd}} slot")
    url = handle.replace("{cmd}", urllib.parse.quote(command))
    r = requests.get(url, timeout=PROBE_TIMEOUT,
                     verify=os.environ.get("REQUESTS_CA_BUNDLE", False))
    # A 5xx is the server erroring, not the shell answering — same reasoning as
    # the bind/ssh transports treating stderr-only as "not an answer". Raise so
    # the probe records a failure, never an empty "it replied".
    if r.status_code >= 500:
        raise ConnectionError(
            f"webshell {handle.split('?')[0]} returned HTTP {r.status_code}")
    return r.text or ""


# ── Generic service-credential probers ──────────────────────────────────────
#
# Access is not only shells. A valid credential to a database, a VNC server, an
# FTP account or any other service is ACCESS TOO — it is reachable, it survives a
# reboot, and it belongs in obtained_access ranked next to shells. These probers
# do not run `id` (the service is not a shell); they authenticate and return a
# marker line the probe understands: `AUTH_OK user=<u> svc=<proto>` when the
# credential logs in, or `REACHABLE svc=<proto>` when the service answers but we
# cannot (yet) prove auth. Each RAISES on failure so the probe records dead.
#
# The point is generality: any protocol with a prober here is captured; anything
# else still gets a TCP-reachability probe rather than being dropped.

# Default TCP port per protocol, for candidates that carry none.
_DEFAULT_PORTS = {
    "ssh": 22, "telnet": 23, "ftp": 21, "ftps": 990, "smtp": 25, "http": 80,
    "https": 443, "mysql": 3306, "mariadb": 3306, "postgres": 5432,
    "postgresql": 5432, "mssql": 1433, "mongodb": 27017, "redis": 6379,
    "vnc": 5900, "rdp": 3389, "smb": 445, "cifs": 445, "ldap": 389,
    "rlogin": 513, "rsh": 514, "elasticsearch": 9200, "memcached": 11211,
}

# Service accounts whose access is privileged (analogue of uid==0 for shells).
_PRIV_USERS = {"root", "sa", "postgres", "administrator", "admin", "system",
               "superuser", "oracle", "mysql"}


def _probe_postgres(target, port, user, secret):
    import psycopg2
    conn = psycopg2.connect(host=target, port=int(port or 5432), user=user or "postgres",
                            password=secret or "", dbname=os.environ.get("PGPROBE_DB", "postgres"),
                            connect_timeout=min(PROBE_TIMEOUT, 15))
    try:
        cur = conn.cursor()
        cur.execute("SELECT current_user, current_setting('is_superuser')")
        u, super_ = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    priv = " priv=1" if str(super_).lower() in ("on", "true", "1") else ""
    return f"AUTH_OK user={u} svc=postgres{priv}"


def _probe_mysql(target, port, user, secret):
    try:
        import pymysql
    except Exception:
        raise ConnectionError("mysql driver (pymysql) not installed — not probed")
    conn = pymysql.connect(host=target, port=int(port or 3306), user=user or "root",
                           password=secret or "", connect_timeout=min(PROBE_TIMEOUT, 15))
    try:
        cur = conn.cursor()
        cur.execute("SELECT CURRENT_USER()")
        u = (cur.fetchone() or [""])[0]
        cur.close()
    finally:
        conn.close()
    return f"AUTH_OK user={u} svc=mysql"


def _probe_ftp(target, port, user, secret):
    from ftplib import FTP
    ftp = FTP()
    ftp.connect(target, int(port or 21), timeout=min(PROBE_TIMEOUT, 15))
    try:
        ftp.login(user or "anonymous", secret or "anonymous@")
        ftp.voidcmd("NOOP")
    finally:
        try:
            ftp.quit()
        except Exception:  # noqa: BLE001
            ftp.close()
    return f"AUTH_OK user={user or 'anonymous'} svc=ftp"


def _probe_redis(target, port, secret):
    import socket
    s = socket.create_connection((target, int(port or 6379)), timeout=min(PROBE_TIMEOUT, 12))
    try:
        if secret:
            s.sendall(f"AUTH {secret}\r\n".encode())
            if b"+OK" not in s.recv(256):
                raise ConnectionError("redis AUTH failed")
        s.sendall(b"PING\r\n")
        if b"+PONG" not in s.recv(64):
            raise ConnectionError("redis did not PONG")
    finally:
        s.close()
    return "AUTH_OK user=default svc=redis"


def _probe_vnc(target, port, secret):
    # RFB reachability: read the ProtocolVersion banner (e.g. 'RFB 003.008').
    # Full DES challenge auth is a follow-up; a reachable RFB with a stored
    # password is recorded as reachable service access, re-probed each cycle.
    import socket
    s = socket.create_connection((target, int(port or 5900)), timeout=min(PROBE_TIMEOUT, 12))
    try:
        banner = s.recv(12)
    finally:
        s.close()
    if not banner.startswith(b"RFB"):
        raise ConnectionError(f"not an RFB service: {banner[:12]!r}")
    return f"REACHABLE svc=vnc ({banner.decode('ascii','replace').strip()})"


def _probe_telnet(target, port, user, secret, command):
    # telnet is a shell: log in and run the command so `uid=` parses like ssh.
    try:
        import telnetlib
    except Exception:
        raise ConnectionError("telnet client (telnetlib) unavailable — not probed")
    tn = telnetlib.Telnet(target, int(port or 23), timeout=min(PROBE_TIMEOUT, 15))
    try:
        tn.read_until(b"login:", timeout=8)
        tn.write((user or "") + "\n")
        tn.read_until(b"assword:", timeout=8)
        tn.write((secret or "") + "\n")
        tn.write(command.encode() + b"\n")
        tn.write(b"exit\n")
        return tn.read_all().decode("utf-8", "replace")
    finally:
        tn.close()


def _probe_tcp(target, port, proto):
    import socket
    if not port:
        raise ConnectionError(f"no port to probe for {proto}")
    s = socket.socket()
    s.settimeout(min(PROBE_TIMEOUT, 10))
    try:
        s.connect((target, int(port)))
    finally:
        s.close()
    return f"REACHABLE svc={proto}"


def _run_credential(handle: str, command: str, **kw) -> str:
    """Generic service credential. handle = 'proto:user:secret' (secret may
    contain ':'). Dispatches to the per-protocol prober; unknown protocols fall
    back to TCP reachability rather than being dropped."""
    target = kw.get("target") or ""
    port = kw.get("port")
    proto, _, rest = handle.partition(":")
    user, _, secret = rest.partition(":")
    proto = (proto or "").strip().lower()
    port = port or _DEFAULT_PORTS.get(proto)
    if proto == "ssh":
        return _run_ssh_credential(f"{user}:{secret}", command, target=target, port=port or 22)
    if proto in ("telnet", "rlogin", "rsh"):
        return _probe_telnet(target, port, user, secret, command)
    if proto in ("postgres", "postgresql"):
        return _probe_postgres(target, port, user, secret)
    if proto in ("mysql", "mariadb"):
        return _probe_mysql(target, port, user, secret)
    if proto in ("ftp", "ftps"):
        return _probe_ftp(target, port, user, secret)
    if proto == "redis":
        return _probe_redis(target, port, secret)
    if proto == "vnc":
        return _probe_vnc(target, port, secret)
    return _probe_tcp(target, port, proto)


TRANSPORTS: Dict[str, Callable[..., str]] = {
    "msf_session": _run_msf,
    "bind_shell": _run_bind_shell,
    "ssh_credential": _run_ssh_credential,
    "listener_callback": _run_listener_callback,
    "webshell": _run_webshell,
    "credential": _run_credential,
}


# Prefer the Kali container. It is the one with the tools: autogen-agents has
# `nc` but no `ssh` and no `sshpass`, so probing from there scores every SSH
# credential zero and ranks the access wrongly — a shell gets chosen because the
# others could not be tested, not because it was better.
#
# Local execution stays as the fallback for when the listener is unreachable,
# and says so, because a probe that could not run is not a shell that did not
# answer.
PREFER_LISTENER = os.environ.get("ACCESS_PREFER_LISTENER", "1") != "0"


def _run_via_listener(access: Dict[str, Any], command: str) -> Optional[Dict[str, Any]]:
    """Ask the Kali container to run it. None when the listener cannot be asked."""
    # The generic `credential` transport is python-based (psycopg2/ftplib/socket)
    # and self-contained, so it runs locally rather than through the listener,
    # which does not know this kind and would refuse it.
    if access.get("kind") == "credential":
        return None
    if not (PREFER_LISTENER and KALI_LISTENER_URL):
        return None
    try:
        import requests
        r = requests.post(
            f"{KALI_LISTENER_URL.rstrip('/')}/access/run",
            json={"kind": access.get("kind"), "handle": access.get("handle"),
                  "command": command, "target": access.get("target"),
                  "port": access.get("port")},
            timeout=PROBE_TIMEOUT + 10,
            headers={"x-api-key": os.environ.get("API_KEY", "")},
            verify=os.environ.get("REQUESTS_CA_BUNDLE", False))
        if r.status_code == 400:
            # The listener refused the transport. That is an answer, not a
            # reason to try it locally with a different one.
            return {"ok": False, "output": "", "error": r.text[:300],
                    "via": "kali-listener"}
        if r.status_code != 200:
            return None
        body = r.json() or {}
        return {"ok": bool(body.get("ok")), "output": body.get("output") or "",
                "error": body.get("error") or "", "via": "kali-listener"}
    except Exception as e:  # noqa: BLE001
        log.debug("listener access run failed, falling back locally: %s", e)
        return None


def _have_local_tool(kind: str) -> bool:
    """Whether THIS container can run that transport at all.

    Saying "the shell did not answer" when the tool to reach it is not installed
    is the same mistake as recording an unparsed run as fruitless — a probe that
    could not run is not a negative result.
    """
    import shutil
    needed = {"bind_shell": "nc", "ssh_credential": "sshpass"}.get(kind)
    return needed is None or shutil.which(needed) is not None


def run(access: Dict[str, Any], command: str) -> Dict[str, Any]:
    """Run one command through one access. Never raises.

    ``{"ok", "output", "error", "via"}``. Routed through the Kali container by
    preference; a transport with no runner is refused rather than falling back
    to something else, because a silent fallback would mean the operator
    believes a command ran through the access they chose when it ran through a
    different one.
    """
    kind = access.get("kind") or ""
    if kind not in TRANSPORTS:
        return {"ok": False, "output": "", "via": "none",
                "error": f"unsupported transport: {kind!r}"}

    remote = _run_via_listener(access, command)
    if remote is not None:
        return remote

    if not _have_local_tool(kind):
        return {"ok": False, "output": "", "via": "local",
                "error": (f"cannot reach a {kind} from this container and the "
                          f"kali-listener is unavailable — not probed, which is "
                          f"not the same as not answering")}
    try:
        out = TRANSPORTS[kind](access.get("handle") or "", command,
                               target=access.get("target"),
                               port=access.get("port"))
        return {"ok": True, "output": out or "", "error": "", "via": "local"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "output": "", "via": "local",
                "error": f"{type(e).__name__}: {e}"[:300]}


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
             "ssh_credential": 3, "webshell": 1, "credential": 2, "bind_shell": 0}.get(kind, 0)
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
    is_root = None
    last_error = ""
    for _ in range(max(1, rounds)):
        res = run(access, "id; uname -a")
        if not res["ok"]:
            last_error = res["error"]
            continue
        text = res["output"]
        if not text.strip():
            # It "succeeded" and said nothing. A channel that returns an empty
            # string has not demonstrated it is access, and counting it would
            # rank silence above no access at all.
            last_error = "empty response"
            continue
        m = _UID_RE.search(text)
        if m:
            # A shell: privilege from uid.
            ok += 1
            uid = int(m.group(1))
            is_root = (uid == 0)
            w = _WHOAMI_RE.search(text)
            whoami = w.group(1) if w else whoami
            for line in text.splitlines():
                if line.lower().startswith("linux") or " gnu/linux" in line.lower():
                    os_info = line.strip()[:200]
                    break
            continue
        am = _AUTH_RE.search(text)
        if am:
            # A service credential that authenticated. Privilege from the account.
            ok += 1
            u = (am.group("user") or "").strip()
            if u and not whoami:
                whoami = u
            if is_root is None:
                is_root = bool(_PRIV_RE.search(text)) or (bool(u) and u.lower() in _PRIV_USERS)
            continue
        if _REACH_RE.search(text):
            # Reachable but auth unproven — a responding channel, unknown priv.
            ok += 1
            last_error = "reachable, auth unproven"
            continue
        # It answered, but not with anything recognisable. A responding channel
        # with unknown privilege, not a failure.
        last_error = "no uid/auth in response"
        ok += 1
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

        # 3. Credentials — for ANY service, not just ssh. A valid credential to a
        #    database, VNC, FTP, redis, etc. is access that survives a reboot and
        #    belongs in obtained_access ranked with shells. Do NOT filter on
        #    valid_cred: the model MEASURES (probe decides live/dead), so an
        #    unverified or even previously-failed credential is a candidate to be
        #    re-checked, not pre-judged. ssh stays its own kind (the listener has
        #    sshpass); everything else routes through the generic prober.
        try:
            cur.execute(
                """SELECT username, secret_value, port, LOWER(COALESCE(protocol,'ssh')),
                          COALESCE(secret_type,'')
                     FROM credential_findings
                    WHERE host(ip) = %s AND secret_value IS NOT NULL
                    ORDER BY valid_cred DESC NULLS LAST, created_at DESC LIMIT 25""",
                (target,))
            for username, secret, port, proto, stype in cur.fetchall():
                proto = (proto or "ssh").strip().lower()
                # A crypt HASH ($1$/$5$/$6$/$y$/$2$…) is a crack target, not a
                # login — using it as a password just probes dead. Skip it (and
                # non-secret junk); a cracked plaintext comes back as a real
                # 'password' credential the next sweep offers.
                if _is_crypt_hash(secret) or (stype or "").lower() not in ("password", ""):
                    continue
                if proto == "ssh":
                    found.append({"target": target, "port": port or 22,
                                  "kind": "ssh_credential",
                                  "handle": f"{username}:{secret}",
                                  "transport": "ssh"})
                else:
                    found.append({"target": target,
                                  "port": port or _DEFAULT_PORTS.get(proto),
                                  "kind": "credential",
                                  "handle": f"{proto}:{username}:{secret}",
                                  "transport": proto})
        except Exception as e:  # noqa: BLE001
            log.debug("credential discovery failed: %s", e)

        # 4. Web shells: a PHP shell an exploit planted, addressable by a URL
        #    with a {cmd} slot (exploit-runner records it as session_id on a
        #    successful webshell result). Proven RCE that was NOT held access
        #    before this transport existed — sourcing it here makes a planted
        #    web shell durable and rankable alongside bind/ssh/msf.
        try:
            cur.execute(
                """SELECT pe.target_ip, pe.target_port, er.session_id
                     FROM exploit_results er
                     JOIN pending_exploits pe ON pe.id = er.pending_exploit_id
                    WHERE er.session_type = 'webshell' AND er.success = true
                      AND er.session_id IS NOT NULL AND pe.target_ip = %s
                    ORDER BY er.created_at DESC LIMIT 3""", (target,))
            for _tip, tport, url in cur.fetchall():
                found.append({"target": target, "port": tport or 80,
                              "kind": "webshell",
                              "handle": url,
                              "transport": "http"})
        except Exception as e:  # noqa: BLE001
            log.debug("webshell discovery failed: %s", e)
    finally:
        if own and conn is not None:
            conn.close()
    return found


# Access kinds that ARE command execution (a shell/session), as opposed to a
# service credential. A shell is RCE; root makes it critical.
_SHELL_KINDS = {"bind_shell", "msf_session", "webshell", "listener_callback"}


def _access_severity_title(row: Dict[str, Any]) -> tuple:
    """(severity, title) for a held access, so it reads as a finding.

    A root shell is the highest-impact result there is — critical. A non-root
    shell or an interactive SSH login is high (command execution / a foothold).
    A non-shell service credential (db, ftp, vnc, redis, telnet) is medium: real
    access, but not code execution on its own.
    """
    kind = row.get("kind") or ""
    whoami = row.get("whoami")
    port = row.get("port")
    target = row.get("target") or ""
    transport = row.get("transport") or kind
    at = f":{port}" if port else ""
    if row.get("is_root"):
        return "critical", f"Remote ROOT access on {target}{at} via {kind}"
    if kind in _SHELL_KINDS:
        return "high", f"Remote shell ({whoami or 'unknown user'}) on {target}{at} via {kind}"
    if kind == "ssh_credential":
        who = f"{whoami}@" if whoami else ""
        return "high", f"Valid SSH login {who}{target} — interactive access"
    return "medium", f"Valid {transport} credential on {target}{at}"


def _emit_access_finding_webhook(target: str, title: str, severity: str,
                                 engagement_id: Optional[str]) -> None:
    """Best-effort webhook for a newly-recorded high/critical access finding."""
    try:
        import requests
        base = os.environ.get("RAG_API_URL", "https://rag-api:8000").rstrip("/")
        key = os.environ.get("API_KEY", "changeme")
        requests.post(f"{base}/webhooks/emit",
                      headers={"x-api-key": key, "Content-Type": "application/json"},
                      json={"event_type": "access_finding_recorded", "source": "access",
                            "severity": severity,
                            "data": {"target": target, "title": title, "severity": severity,
                                     "engagement_id": engagement_id}},
                      timeout=5, verify=False)
    except Exception as e:  # noqa: BLE001
        log.debug("access finding webhook failed: %s", e)


def _sync_access_findings(cur, target: str,
                          engagement_id: Optional[str] = None) -> int:
    """Mirror held access into the findings model so a root shell is a CRITICAL
    finding, not just an obtained_access row.

    For every access on this target: a LIVE one upserts a fingerprinted vuln
    whose severity tracks the access (root shell → critical); a DEAD one resolves
    its finding so the severity view stays truthful. The fingerprint is stable
    per (target, kind, handle), so re-probing updates the same row rather than
    duplicating. Best-effort and side-channel: never raises into refresh()."""
    import hashlib
    from psycopg2.extras import Json
    cur.execute("SELECT id FROM public.assets WHERE host(ip) = %s "
                "ORDER BY last_seen DESC NULLS LAST LIMIT 1", (target,))
    a = cur.fetchone()
    if not a:
        return 0
    asset_id = a[0]
    cur.execute("SELECT kind, handle, port, transport, whoami, uid, is_root, score, status "
                "  FROM public.obtained_access WHERE target = %s", (target,))
    cols = ("kind", "handle", "port", "transport", "whoami", "uid", "is_root",
            "score", "status")
    synced = 0
    for r in cur.fetchall():
        row = dict(zip(cols, r))
        row["target"] = target
        fp = hashlib.md5(
            f"access|{target}|{row['kind']}|{row['handle']}".encode()).hexdigest()
        cur.execute("SELECT id FROM public.vulns WHERE fingerprint = %s", (fp,))
        ex = cur.fetchone()
        if row["status"] == "live":
            sev, title = _access_severity_title(row)
            port_id = None
            if row.get("port"):
                cur.execute("SELECT id FROM public.ports WHERE asset_id = %s AND port = %s "
                            "LIMIT 1", (asset_id, row["port"]))
                pr = cur.fetchone()
                port_id = pr[0] if pr else None
            output = (f"Held access via {row['kind']} ({row.get('transport') or ''}). "
                      f"whoami={row.get('whoami')}, uid={row.get('uid')}, "
                      f"is_root={row.get('is_root')}, score={row.get('score')}, status=live.")
            meta = {"source": "access_bridge", "access_kind": row["kind"],
                    "handle": row["handle"], "whoami": row.get("whoami"),
                    "is_root": bool(row.get("is_root")), "score": row.get("score"),
                    "port": row.get("port"), "transport": row.get("transport")}
            if ex:
                cur.execute(
                    """UPDATE public.vulns
                          SET severity = %s, title = %s, output = %s, metadata = %s,
                              port_id = COALESCE(%s, port_id), last_seen = now()
                        WHERE id = %s""",
                    (sev, title, output, Json(meta), port_id, ex[0]))
            else:
                cur.execute(
                    """INSERT INTO public.vulns
                          (asset_id, port_id, script, output, severity, title, metadata,
                           fingerprint, workflow_status, engagement_id, first_seen, last_seen)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'new',%s,now(),now())""",
                    (asset_id, port_id, f"access:{row['kind']}", output, sev, title,
                     Json(meta), fp, engagement_id))
                if sev in ("critical", "high"):
                    _emit_access_finding_webhook(target, title, sev, engagement_id)
            synced += 1
        elif ex:
            # Access is gone — DELETE the finding. It asserts LIVE access; a dead
            # one is no longer true. (An earlier version set workflow_status =
            # 'resolved', which is not an allowed value for that column and raised
            # a CheckViolation wherever the constraint is applied.)
            cur.execute("DELETE FROM public.vulns WHERE id = %s", (ex[0],))
    return synced


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
                probed = set()
                for cand in candidates:
                    probed.add((cand["kind"], cand["handle"]))
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

                # Reconcile what we still THINK we hold. A row that drops out of
                # discovery (a candidate we no longer offer — e.g. a UDP port we
                # used to mis-offer as a bind shell) would otherwise linger as a
                # phantom "live", outranking real access, because nothing
                # re-probes it. refresh means "re-verify everything on this
                # target", so re-probe those too; a refused/silent one goes dead.
                cur.execute(
                    "SELECT kind, handle, port, transport "
                    "  FROM public.obtained_access "
                    " WHERE target = %s AND status = 'live'", (target,))
                stale = [r for r in cur.fetchall() if (r[0], r[1]) not in probed]
                for kind, handle, port, transport in stale:
                    result = probe({"kind": kind, "handle": handle, "port": port,
                                    "transport": transport or ""}, rounds=rounds)
                    cur.execute(
                        """
                        UPDATE public.obtained_access SET
                          whoami = %s, uid = %s, is_root = %s, os_info = %s,
                          probes = probes + %s, probes_ok = probes_ok + %s,
                          last_probe_at = now(), last_error = %s, score = %s,
                          status = CASE WHEN status = 'rejected' THEN 'rejected'
                                        ELSE %s END
                         WHERE target = %s AND kind = %s AND handle = %s
                        """,
                        (result["whoami"], result["uid"], result["is_root"],
                         result["os_info"], result["probes"], result["probes_ok"],
                         result["last_error"], result["score"], result["status"],
                         target, kind, handle))
                    if result["status"] != "live":
                        out["dead"] += 1
                        out["reconciled_dead"] = out.get("reconciled_dead", 0) + 1

                # Mirror held access into the findings model (root shell → a
                # CRITICAL finding). Side-channel: a failure here must not fail
                # the refresh, which is the authoritative access record.
                try:
                    out["findings_synced"] = _sync_access_findings(
                        cur, target, engagement_id)
                except Exception as e:  # noqa: BLE001
                    log.warning("access->finding sync failed for %s: %s", target, e)
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


def record_exploit_success_finding(target: str, port, service: str,
                                   label: str, output: str,
                                   session_type: str = None) -> bool:
    """Tag a successful exploit as a FINDING even when it left no persistent shell.

    A one-shot RCE (distcc, php_cgi, java_rmi, unrealircd, a webshell command) is a
    real result — command execution was proven — so it is recorded as a vuln
    finding that drives the asset banner's severity, distinct from a live session
    (which lives in obtained_access). Idempotent per (ip, port, label) via a stable
    fingerprint. Best-effort; returns True if a finding was written.

    severity: root in the output -> critical; a command-execution exploit -> high;
    a pure auxiliary/scanner confirmation -> medium (not command execution)."""
    import hashlib
    from psycopg2.extras import Json
    ip = str(target or "").split("/")[0]
    lab = (label or "exploit").strip()
    low = f"{lab} {output or ''}".lower()
    is_aux = "auxiliary/" in lab.lower() or "scanner/" in lab.lower()
    is_root = ("uid=0(root)" in low or "whoami\nroot" in low
               or "\nroot\n" in low or low.strip().endswith(" root")
               or '"whoami":"root"' in low)
    if is_root:
        sev = "critical"
    elif is_aux:
        sev = "medium"
    else:
        sev = "high"
    kind = "service_confirmed" if is_aux else "command_exec"
    verb = "Service issue confirmed" if is_aux else "Command execution confirmed"
    persistent = bool(session_type and session_type not in ("", "none", "web_poc"))
    title = (f"{verb} on {ip}" + (f":{port}" if port else "")
             + f" via {lab}" + (" (persistent session)" if persistent else ""))
    fp = hashlib.md5(f"exploit_success|{ip}|{port or ''}|{lab}".encode()).hexdigest()
    conn = None
    try:
        conn = _connect(); conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT id, engagement_id FROM public.assets WHERE host(ip) = %s LIMIT 1", (ip,))
        a = cur.fetchone()
        if not a:
            return False
        asset_id, engagement_id = a[0], a[1]
        port_id = None
        if port:
            cur.execute("SELECT id FROM public.ports WHERE asset_id = %s AND port = %s LIMIT 1",
                        (asset_id, int(port)))
            pr = cur.fetchone(); port_id = pr[0] if pr else None
        meta = {"source": "exploit_success", "kind": kind, "exploit": lab,
                "port": port, "service": service, "persistent_shell": persistent}
        out = (f"{verb} via {lab}"
               + (f" on {service}" if service else "")
               + (". A persistent session was opened." if persistent
                  else ". Command execution was proven; no persistent shell.")
               + (f"\n--- output ---\n{(output or '')[:1500]}" if output else ""))
        cur.execute("SELECT id FROM public.vulns WHERE fingerprint = %s", (fp,))
        ex = cur.fetchone()
        if ex:
            cur.execute("""UPDATE public.vulns SET severity=%s, title=%s, output=%s,
                             metadata=%s, port_id=COALESCE(%s, port_id), last_seen=now()
                           WHERE id=%s""",
                        (sev, title, out, Json(meta), port_id, ex[0]))
        else:
            cur.execute("""INSERT INTO public.vulns
                             (asset_id, port_id, script, output, severity, title, metadata,
                              fingerprint, workflow_status, engagement_id, first_seen, last_seen)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'new',%s,now(),now())""",
                        (asset_id, port_id, f"exploit:{kind}", out, sev, title,
                         Json(meta), fp, engagement_id))
        cur.close()
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("record_exploit_success_finding failed for %s: %s", ip, e)
        return False
    finally:
        if conn:
            conn.close()
