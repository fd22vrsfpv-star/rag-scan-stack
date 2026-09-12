"""
Credential Testing Module
Tests default and weak credentials for common services.
"""

import os
import re
import threading      # scan-slot semaphore, see _cred_scan_slot()
from contextlib import contextmanager
import subprocess
import logging
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cred_checker")


# =============================================================================
# Default Credentials Database
# =============================================================================

# Default credentials for common services
# Format: service -> [(username, password), ...]
DEFAULT_CREDENTIALS: Dict[str, List[Tuple[str, str]]] = {
    "ssh": [
        ("msfadmin", "msfadmin"),
        ("root", "root"),
        ("root", "toor"),
        ("admin", "admin"),
        ("user", "user"),
        ("test", "test"),
        ("ubuntu", "ubuntu"),
        ("vagrant", "vagrant"),
    ],
    "ftp": [
        ("anonymous", ""),
        ("anonymous", "anonymous@"),
        ("ftp", "ftp"),
        ("msfadmin", "msfadmin"),
        ("admin", "admin"),
        ("root", "root"),
    ],
    "telnet": [
        ("msfadmin", "msfadmin"),
        ("root", "root"),
        ("admin", "admin"),
        ("user", "user"),
    ],
    "mysql": [
        ("root", ""),
        ("root", "root"),
        ("root", "mysql"),
        ("root", "password"),
        ("mysql", "mysql"),
        ("admin", "admin"),
    ],
    "postgres": [
        ("postgres", "postgres"),
        ("postgres", ""),
        ("postgres", "password"),
        ("admin", "admin"),
    ],
    "vnc": [
        ("", "password"),
        ("", "vnc"),
        ("", "123456"),
        ("", "1234"),
    ],
    "tomcat": [
        ("tomcat", "tomcat"),
        ("admin", "admin"),
        ("manager", "manager"),
        ("tomcat", "s3cret"),
        ("admin", ""),
        ("role1", "role1"),
    ],
    "smb": [
        ("", ""),  # Null session
        ("guest", ""),
        ("administrator", ""),
        ("admin", "admin"),
    ],
    "redis": [
        ("", ""),  # No auth
    ],
    "mongodb": [
        ("", ""),  # No auth
        ("admin", "admin"),
        ("root", "root"),
    ],
    "mssql": [
        ("sa", ""),
        ("sa", "sa"),
        ("sa", "password"),
        ("sa", "Password123"),
    ],
}


# Service port mappings
SERVICE_PORTS: Dict[str, List[int]] = {
    "ssh": [22, 2222],
    "ftp": [21, 2121],
    "telnet": [23, 2323],
    "mysql": [3306, 33060],
    "postgres": [5432, 5433],
    "vnc": [5900, 5901, 5902],
    "tomcat": [8080, 8180, 8443],
    "smb": [445, 139],
    "redis": [6379],
    "mongodb": [27017],
    "mssql": [1433, 1434],
}


@dataclass
class CredentialResult:
    """Result of a credential check"""
    service: str
    target: str
    port: int
    username: str
    password: str
    success: bool
    method: str  # 'hydra', 'nmap', 'netcat', etc.
    details: Optional[str] = None


# ── Scope gate ────────────────────────────────────────────────────────────
#
# This module subprocesses straight to a target, so nothing downstream can
# refuse on its behalf. The matcher is shared (etl/scope_gate.py, bind-mounted
# at /app/etl) and enforce_target_scope does its own DB lookup, so adopting it
# costs one line per dispatch.
#
# FAILS CLOSED: if the gate cannot be imported we refuse, because a missing
# mount must not be indistinguishable from an authorised target.
try:
    from etl.scope_gate import enforce_target_scope
    _SCOPE_GATE_OK = True
except Exception as _scope_exc:      # pragma: no cover - deployment problem
    _SCOPE_GATE_OK = False
    _SCOPE_GATE_ERROR = str(_scope_exc)


# ── Scan-volume bound ───────────────────────────────────────────────────────
# This module subprocesses hydra straight at a host, so it IS a scan initiator
# and must respect the engagement ceiling rather than invent one. `common/` is
# not mounted into nmap-scanner, so the semaphore is built here from the SAME
# env var common/tool_job.py reads — the number is shared even though the
# counter cannot be. That limitation is the same one tool_job documents: the
# bound is PER PROCESS, so two initiators at the limit still total 2N.
#
# Credential checks WAIT for a slot rather than being shed: they run inside an
# already-accepted scan, and dropping one would silently skip a service the
# operator asked to be tested.
MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))
_CRED_SLOT_WAIT_S = int(os.environ.get("SCAN_SLOT_WAIT_TIMEOUT", "1800"))
_cred_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


@contextmanager
def _cred_scan_slot(label: str = "cred-check"):
    """Hold one of MAX_CONCURRENT_SCANS slots for the duration of a check."""
    if not _cred_slots.acquire(timeout=_CRED_SLOT_WAIT_S):
        raise TimeoutError(
            f"{label}: no scan slot within {_CRED_SLOT_WAIT_S}s "
            f"(MAX_CONCURRENT_SCANS={MAX_CONCURRENT_SCANS})")
    try:
        yield
    finally:
        _cred_slots.release()


def _scope_refusal(target: str = "", command: str = ""):
    """Refusal string when this must not be sent, else None."""
    if not _SCOPE_GATE_OK:
        return (f"scope gate unavailable ({_SCOPE_GATE_ERROR}) — refusing to "
                "send traffic; check the ./etl:/app/etl mount")
    return enforce_target_scope(target, command)


def get_service_from_port(port: int) -> Optional[str]:
    """Infer service type from port number"""
    for service, ports in SERVICE_PORTS.items():
        if port in ports:
            return service
    return None


def _mask_password(password: str) -> str:
    """Operator-friendly password masking for audit logs.

    Goal: enough information that an operator scanning the audit recognises
    which password from their wordlist was tried (length + leading chars),
    without preserving the secret in plaintext if the audit ends up in logs
    or DB rows that get exfiltrated.  Successful credentials' full passwords
    remain in the in-memory job record + on-disk JSON, NOT here.

      ""        -> "(empty)"
      "a"       -> "*"
      "ab"      -> "**"
      "abc"     -> "***"
      "abcd"    -> "ab**"          (first 2 + asterisks for the rest)
      "msfadmin"-> "msf*****"       (first 3 + asterisks for the rest)
    """
    if not password:
        return "(empty)"
    n = len(password)
    if n <= 3:
        return "*" * n
    keep = 2 if n == 4 else 3
    return password[:keep] + ("*" * (n - keep))


# How much of a tool's own output is kept as proof that a credential works.
# Bounded because this lands in a jsonb column that is read by every listing
# endpoint: 127MB of stderr once made two pages unservable, and an operator does
# not need the whole run to believe one line.
EVIDENCE_CHARS = 400


def _redact_secret(line: str, username: str, password: str) -> str:
    """Mask the password inside a tool's own output line.

    Capturing the tool's proof re-exposed the secret somewhere the UI does not
    mask it: hydra prints "login: msfadmin   password: msfadmin" and nmap prints
    "msfadmin:msfadmin - Valid credentials", and the evidence block renders both
    verbatim. `SecretValue` hides the password behind a deliberate Reveal click
    precisely because this panel is on screen during screen-shares and report
    writing; an unmasked copy two rows above it defeats that entirely.

    Only the password is touched, and only where a label or the `user:pass`
    separator identifies it as the password. A blunt string replacement would
    mangle `anonymous` / `anonymous@`, where the username and secret overlap.
    """
    if not line or not password:
        return line
    masked = _mask_password(password)
    esc_pw = re.escape(password)
    patterns = [
        # hydra:  "... password: msfadmin"
        (re.compile(rf"((?:pass(?:word)?|passwd)\s*[:=]\s*){esc_pw}", re.I), masked),
    ]
    if username:
        # nmap NSE: "msfadmin:msfadmin - Valid credentials"
        patterns.append(
            (re.compile(rf"({re.escape(username)}\s*:\s*){esc_pw}\b"), masked))
    for rx, repl in patterns:
        line = rx.sub(lambda m: m.group(1) + repl, line)
    return line


def _confirming_line(output: str, username: str, markers: Tuple[str, ...],
                     password: str = "") -> Optional[str]:
    """The line where the tool said this account worked.

    An audit that records `success: true` and nothing else asks the operator to
    take the platform's word for it. What makes a credential reportable is the
    tool's own sentence, so keep that sentence rather than the name of the
    script that produced it.
    """
    if not output or not username:
        return None
    for line in output.splitlines():
        low = line.lower()
        if username.lower() in low and any(m in low for m in markers):
            return _redact_secret(line.strip(), username, password)[:EVIDENCE_CHARS]
    # The account matched nothing quotable; fall back to any line that announced
    # a success, which is still better than asserting it with no text at all.
    for line in output.splitlines():
        if any(m in line.lower() for m in markers):
            return _redact_secret(line.strip(), username, password)[:EVIDENCE_CHARS]
    return None


def _sanitised_command(cmd: List[str], secrets: Tuple[str, ...] = ()) -> str:
    """The command line, with any literal secret replaced.

    Provenance is part of the finding (CLAUDE.md: "command line (sanitized)"),
    but hydra takes the password as an argument, so the raw argv would put the
    secret into an audit blob that is shown on screen and exported.
    """
    out = []
    for part in cmd:
        for sec in secrets:
            if sec and part == sec:
                part = "<redacted>"
        out.append(part)
    return " ".join(out)[:EVIDENCE_CHARS]


def _classify_hydra_failure(output: str) -> Tuple[str, Optional[str]]:
    """Inspect hydra stdout+stderr to LABEL why a single attempt failed.

    This is presentation, not policy. It exists so the audit panel can say
    "couldn't even handshake" instead of "wrong password", and nothing branches
    on its answer any more. Which tool to try next is decided from the raw error
    text by etl/tool_learning.py, which knows no protocol vocabulary — so a
    service this function has never heard of still gets a working fallback.

    Returns ``(failure_mode, error_excerpt)``.  failure_mode is one of:
      - "kex_mismatch": SSH key-exchange / host-key-algorithm negotiation
        failed; typically legacy SSH servers (Metasploitable2, OpenSSH < 7.0)
        offering ssh-rsa/dss while modern hydra/libssh only offers ed25519
        and rsa-sha2-*.  No password was actually tested.
      - "connection_error": couldn't reach the service at all (closed port,
        timeout at TCP/SSL layer, host unreachable).
      - "auth_failed": connected + completed protocol negotiation, but the
        credential was rejected.  This is the "normal" failure for wrong
        credentials.
      - "unknown": hydra returned 0 valid passwords but the output didn't
        match any of the above patterns.
    """
    low = output.lower()
    # SSH KEX / host-key-algo mismatch -- exact strings that hydra/libssh emit
    if ("kex error" in low) or ("no match for method" in low) or \
       ("could not connect" in low and "ssh://" in low) or \
       ("no kex algorithm" in low):
        # Pull just the kex-error line so the audit shows it cleanly
        for line in output.splitlines():
            if "kex" in line.lower() or "no match for method" in line.lower():
                return "kex_mismatch", line.strip()[:180]
        return "kex_mismatch", "key exchange failed (legacy SSH algorithms)"
    if "could not connect" in low or "no route to host" in low or \
       "connection refused" in low or "timed out" in low:
        for line in output.splitlines():
            if any(kw in line.lower() for kw in
                   ("could not connect", "no route", "refused", "timed out")):
                return "connection_error", line.strip()[:180]
        return "connection_error", None
    if "0 valid passwords" in low or "0 valid pairs" in low or \
       "login fail" in low:
        return "auth_failed", None
    return "unknown", output.strip()[:180] if output.strip() else None


# Tuple type alias for the rich return shape -- (results, audit_dict).
# Existing callers within this module are updated below; cred_checker.py
# has no external callers (confirmed via repo-wide grep).
HydraResult = Tuple[List["CredentialResult"], Dict[str, Any]]


def check_credentials_hydra(
    target: str,
    port: int,
    service: str,
    credentials: List[Tuple[str, str]],
    timeout: int = 60
) -> HydraResult:
    """
    Test credentials using Hydra.  Returns BOTH the successful credential
    list AND a rich per-attempt audit dict so the operator can see exactly
    which (username, password-masked) pairs were tried, which failed and
    why, and whether a legacy-SSH key-exchange mismatch suppressed real
    auth attempts (the Metasploitable2 case).

    Audit dict shape:
      {
        "method": "hydra",
        "attempts": [
            {"username": "...", "password_masked": "...",
             "success": bool, "failure_mode": "...", "error_excerpt": "..."},
            ...
        ],
        "kex_legacy_detected": bool,     # true if any attempt got kex_mismatch
      }

    Args:
        target: Target IP address
        port: Target port
        service: Service type (ssh, ftp, mysql, etc.)
        credentials: List of (username, password) tuples
        timeout: Timeout in seconds

    Returns:
        Tuple of (successful credential results, audit dict).
    """
    refusal = _scope_refusal(target)
    if refusal:
        logger.warning("REFUSED hydra against %s: %s", target, refusal)
        return []

    with _cred_scan_slot(f"hydra {target}:{port}"):
        return _check_credentials_slotted(target, port, service, credentials, timeout)


def _check_credentials_slotted(target, port, service, credentials, timeout):
    """Body of the credential check, inside the scope gate and a scan slot."""
    results: List[CredentialResult] = []
    audit_attempts: List[Dict[str, Any]] = []
    kex_legacy_detected = False

    # Map our service names to Hydra service names
    hydra_service_map = {
        "ssh": "ssh",
        "ftp": "ftp",
        "telnet": "telnet",
        "mysql": "mysql",
        "postgres": "postgres",
        "vnc": "vnc",
        "smb": "smb",
        "mssql": "mssql",
    }

    hydra_svc = hydra_service_map.get(service)
    if not hydra_svc:
        logger.warning(f"Hydra does not support service: {service}")
        return results, {
            "method": "hydra",
            "attempts": [],
            "kex_legacy_detected": False,
            "unsupported_service": service,
        }

    for username, password in credentials:
        attempt: Dict[str, Any] = {
            "username": username,
            "password_masked": _mask_password(password),
            "success": False,
            "failure_mode": None,
            "error_excerpt": None,
        }
        try:
            # Build hydra command
            # -l: single username, -p: single password, -s: port, -t: tasks
            cmd = ["hydra", "-l", username, "-p", password, "-s", str(port), "-t", "1", "-f"]

            # VNC doesn't use username
            if service == "vnc":
                cmd = ["hydra", "-P", "-", "-s", str(port), "-t", "1", "-f"]

            cmd.extend([target, hydra_svc])

            logger.debug(f"Running: {' '.join(cmd)}")

            # For VNC, pipe the password
            if service == "vnc":
                proc = subprocess.run(
                    cmd,
                    input=password + "\n",
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
            else:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            # Check for success indicators in output
            output = proc.stdout + proc.stderr
            success = "successfully" in output.lower() or "1 valid password" in output.lower()

            if success:
                proof = _confirming_line(
                    output, username,
                    ("successfully", "valid password", "login:", "host:"), password)
                result = CredentialResult(
                    service=service,
                    target=target,
                    port=port,
                    username=username,
                    password=password if password else "(empty)",
                    success=True,
                    method="hydra",
                    details=proof or _redact_secret(
                        output.strip(), username, password)[:EVIDENCE_CHARS]
                )
                results.append(result)
                attempt["success"] = True
                # The sentence hydra printed when it accepted the account, and
                # the command that produced it. An audit that says success and
                # shows nothing asks the operator to take it on faith.
                attempt["evidence"] = proof or _redact_secret(
                    output.strip(), username, password)[:EVIDENCE_CHARS]
                attempt["command"] = _sanitised_command(cmd, (password,))
                logger.info(f"[+] Valid credentials found: {username}:{password} on {target}:{port} ({service})")
            else:
                # Classify the failure so the operator can distinguish
                # "wrong password" from "couldn't even handshake".
                mode, excerpt = _classify_hydra_failure(output)
                attempt["failure_mode"] = mode
                attempt["error_excerpt"] = excerpt
                if mode == "kex_mismatch":
                    kex_legacy_detected = True

        except subprocess.TimeoutExpired:
            logger.warning(f"Hydra timeout for {username}@{target}:{port}")
            attempt["failure_mode"] = "timeout"
        except Exception as e:
            logger.error(f"Hydra error: {e}")
            attempt["failure_mode"] = "unknown"
            attempt["error_excerpt"] = f"{type(e).__name__}: {str(e)[:120]}"

        audit_attempts.append(attempt)

    audit = {
        "method": "hydra",
        "attempts": audit_attempts,
        "kex_legacy_detected": kex_legacy_detected,
    }
    return results, audit


def check_credentials_nmap(
    target: str,
    port: int,
    service: str,
    credentials: List[Tuple[str, str]],
    timeout: int = 120
) -> Tuple[List[CredentialResult], Dict[str, Any]]:
    """
    Test credentials using nmap NSE brute scripts.  Returns BOTH the
    successful credential list AND a per-attempt audit dict, matching
    the shape returned by check_credentials_hydra so the upstream caller
    can present one consistent audit panel regardless of which method
    succeeded.

    Audit dict shape:
      {
        "method": "nmap",
        "script": "ssh-brute",       # which NSE script was run
        "attempts": [                # ALL (user, pass) pairs that went into
            ...                      # the temp userdb/passdb -- nmap doesn't
        ],                           # report per-attempt outcome so most
                                     # rows have success=false and the
                                     # successful ones get success=true
                                     # after parsing nmap's output.
      }

    nmap's brute scripts don't emit per-attempt logs by default, so we
    can't classify individual failures as kex/connection/auth like hydra.
    The audit instead captures the full Cartesian product that was
    submitted plus the parsed successes.
    """
    refusal = _scope_refusal(target)
    if refusal:
        logger.warning("REFUSED nmap against %s: %s", target, refusal)
        return []

    results: List[CredentialResult] = []
    audit_attempts: List[Dict[str, Any]] = []

    # Map services to nmap scripts
    nmap_script_map = {
        "ssh": "ssh-brute",
        "ftp": "ftp-brute",
        "mysql": "mysql-brute",
        "postgres": "pgsql-brute",
        "vnc": "vnc-brute",
        "smb": "smb-brute",
        "telnet": "telnet-brute",
    }

    script = nmap_script_map.get(service)
    if not script:
        return results, {
            "method": "nmap",
            "attempts": [],
            "unsupported_service": service,
        }

    # Create temporary credential files
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as users_file:
            users_path = users_file.name
            for username, _ in credentials:
                if username:
                    users_file.write(username + "\n")

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as pass_file:
            pass_path = pass_file.name
            for _, password in credentials:
                pass_file.write(password + "\n")

        # Run nmap brute force script
        cmd = [
            "nmap", "-Pn", "-p", str(port),
            f"--script={script}",
            f"--script-args=userdb={users_path},passdb={pass_path},brute.firstonly=true",
            target
        ]

        logger.debug(f"Running: {' '.join(cmd)}")

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = proc.stdout

        # Build the audit's attempts list -- one entry per (user, pass) tested.
        # Default all to failure; flip to success below for matches found in
        # nmap's output.
        successful_pairs: List[Tuple[str, str]] = []
        evidence_by_pair: Dict[Tuple[str, str], Optional[str]] = {}
        if "Valid credentials" in output or "Accounts:" in output:
            import re
            patterns = [
                r"(\S+):(\S*)\s+-\s+Valid",  # user:pass - Valid
                r"Accounts:.*?(\S+):(\S*)",   # Accounts: user:pass
            ]
            for pattern in patterns:
                matches = re.findall(pattern, output, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    username, password = match
                    successful_pairs.append((username, password))
                    # The tool's own words, not "nmap <script>". `details` used
                    # to name the script that ran, which is provenance, not
                    # proof — an operator writing this up had nothing to quote.
                    proof = _confirming_line(output, username,
                                             ("valid", "accounts:"), password)
                    evidence_by_pair[(username, password)] = proof
                    result = CredentialResult(
                        service=service,
                        target=target,
                        port=port,
                        username=username,
                        password=password if password else "(empty)",
                        success=True,
                        method="nmap",
                        details=proof or f"nmap {script}"
                    )
                    results.append(result)
                    logger.info(f"[+] Valid credentials found: {username}:{password} on {target}:{port}")

        # Now build the per-attempt audit list: every (user, pass) tested,
        # marking the ones that nmap's parser flagged as Valid.
        success_set = {(u, p) for u, p in successful_pairs}
        for username, password in credentials:
            is_success = (username, password) in success_set
            audit_attempts.append({
                "username": username,
                "password_masked": _mask_password(password),
                "success": is_success,
                # nmap doesn't tell us *why* an attempt failed -- mark as
                # auth_failed unless something at the script level errored.
                "failure_mode": None if is_success else "auth_failed",
                "error_excerpt": None,
                # What the tool said when it accepted this account. Only ever
                # present on a success; a failure has nothing to prove.
                "evidence": evidence_by_pair.get((username, password)),
            })

    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap brute timeout for {target}:{port}")
        audit_attempts = [{
            "username": u,
            "password_masked": _mask_password(p),
            "success": False,
            "failure_mode": "timeout",
            "error_excerpt": None,
        } for u, p in credentials]
    except Exception as e:
        logger.error(f"Nmap brute error: {e}")
        audit_attempts = [{
            "username": u,
            "password_masked": _mask_password(p),
            "success": False,
            "failure_mode": "unknown",
            "error_excerpt": f"{type(e).__name__}: {str(e)[:120]}",
        } for u, p in credentials]
    finally:
        # Cleanup temp files
        try:
            os.unlink(users_path)
            os.unlink(pass_path)
        except Exception:
            pass

    audit = {
        "method": "nmap",
        "script": script,
        "attempts": audit_attempts,
    }
    return results, audit


def check_vnc_password(target: str, port: int = 5900, passwords: List[str] = None) -> List[CredentialResult]:
    """
    Test VNC passwords.
    VNC typically uses password-only authentication.
    """
    results = []

    if passwords is None:
        passwords = [p for _, p in DEFAULT_CREDENTIALS.get("vnc", [])]

    for password in passwords:
        try:
            # Use vncviewer or vnc-brute nmap script
            cmd = [
                "nmap", "-Pn", "-p", str(port),
                "--script=vnc-brute",
                f"--script-args=passdb=-",
                target
            ]

            proc = subprocess.run(
                cmd,
                input=password + "\n",
                capture_output=True,
                text=True,
                timeout=30
            )

            if "Valid credentials" in proc.stdout or password in proc.stdout:
                result = CredentialResult(
                    service="vnc",
                    target=target,
                    port=port,
                    username="",
                    password=password,
                    success=True,
                    method="vnc-brute",
                    details="VNC password authentication"
                )
                results.append(result)
                logger.info(f"[+] Valid VNC password found: {password} on {target}:{port}")
                break

        except Exception as e:
            logger.error(f"VNC check error: {e}")

    return results


def check_bindshell(target: str, port: int = 1524, timeout: int = 5) -> CredentialResult:
    """
    Check for open bindshell (instant root access).
    """
    import socket

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Try to receive banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')

        # Send a test command
        sock.send(b"id\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')

        sock.close()

        if "uid=" in response or "root" in response:
            return CredentialResult(
                service="bindshell",
                target=target,
                port=port,
                username="root",
                password="(none - direct shell)",
                success=True,
                method="netcat",
                details=f"Direct shell access! Response: {response[:100]}"
            )
    except Exception as e:
        logger.debug(f"Bindshell check failed: {e}")

    return None


# ── Learned tool selection ─────────────────────────────────────────────────
#
# Which tool to reach for when another one fails is LEARNED from the error text
# (etl/tool_learning.py), not written down here. The rule this replaced —
# "if hydra's output mentions a KEX mismatch, use nmap" — was correct and still
# wrong in kind: it only existed because a human read one message from one tool
# on one protocol once. Nothing taught the platform anything about telnet,
# mysql, vnc or the next tool added, so those kept re-running something that
# could not work and reporting "nothing found".
#
# Adding a method here is now the whole integration: it is offered, tried, and
# its failures are learned from, with no per-service branch to write.
CRED_METHODS = {
    "hydra": check_credentials_hydra,
    "nmap":  check_credentials_nmap,
}
# Declared order for a service nothing has been learned about yet. It is a
# starting point, not a decision — preferred_order() reorders it as soon as the
# observations justify that.
DEFAULT_METHOD_ORDER = ["hydra", "nmap"]


def _method_error_text(m_audit: Dict[str, Any]) -> str:
    """Everything a method said about why it produced nothing.

    Feeds the signature, so it must be the tool's own words. Deliberately
    includes the coarse `failure_mode` label as a line of its own: a tool that
    fails silently still fails the same way twice, and a signature computed from
    an empty string would merge every silent failure into one bucket.
    """
    parts: List[str] = []
    unsupported = m_audit.get("unsupported_service")
    if unsupported:
        parts.append(f"tool does not support service {unsupported}")
    if m_audit.get("error"):
        parts.append(str(m_audit["error"]))
    for a in m_audit.get("attempts", []):
        if a.get("success"):
            continue
        if a.get("error_excerpt"):
            parts.append(str(a["error_excerpt"]))
        elif a.get("failure_mode"):
            parts.append(f"attempt failed: {a['failure_mode']}")
    return "\n".join(parts)


def _tool_learning():
    """The learning module, or None when it cannot be imported.

    Optional by design: cred_checker must keep working — with its declared tool
    order — in an environment where etl/ is not mounted. Selection is not
    authorisation, so degrading here is safe; the scope gate and the engagement
    pre-approval are enforced elsewhere and are not optional.
    """
    try:
        from etl import tool_learning
        return tool_learning
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[cred_checker] tool_learning unavailable: {e}")
        return None


def check_default_credentials(
    target: str,
    port: int,
    service: str = None,
    # "auto" — work through the authorised methods, learning from each failure
    # which one to reach for next. It defaulted to "hydra", which returned after
    # one tool and never reached the fallback at all. Worse, the caller could not
    # override it: check_all_default_credentials() takes no `method` argument, so
    # the value plumbed down from the API request was dropped and this default was
    # what every credential check actually used.
    #
    # Measured against Metasploitable: ssh reported 0 valid credentials.
    # msfadmin:msfadmin WAS tried; it lost to SSH key-exchange negotiation, not to
    # a wrong password, and nmap's NSE brute scripts handle that legacy KEX fine.
    # Fixing the default took the host from 3 valid credentials to 10.
    #
    # Pass "hydra" or "nmap" to force one method and suppress the fallback.
    method: str = "auto"
) -> Dict[str, Any]:
    """
    Check default credentials for a service.

    Args:
        target: Target IP address
        port: Target port
        service: Service type (auto-detected from port if not provided)
        method: 'auto' (default) tries each authorised method in the order
            etl/tool_learning.py has learned for this service, stopping at the
            first that finds something. Naming a method ('hydra' / 'nmap')
            forces it and disables the fallback.

    Returns:
        Dictionary with check results
    """
    if service is None:
        service = get_service_from_port(port)

    if service is None:
        return {
            "error": f"Unknown service for port {port}",
            "port": port,
            "target": target
        }

    credentials = DEFAULT_CREDENTIALS.get(service, [])
    if not credentials:
        return {
            "error": f"No default credentials defined for service: {service}",
            "service": service,
            "port": port,
            "target": target
        }

    logger.info(f"Checking {len(credentials)} credential pairs for {service} on {target}:{port}")

    # Special case for bindshell
    if service == "bindshell" or port == 1524:
        result = check_bindshell(target, port)
        if result:
            return {
                "service": "bindshell",
                "target": target,
                "port": port,
                "credentials_tested": 0,
                "valid_credentials": [{
                    "username": result.username,
                    "password": result.password,
                    "method": result.method,
                    "details": result.details
                }],
                "success": True
            }
        return {
            "service": "bindshell",
            "target": target,
            "port": port,
            "credentials_tested": 0,
            "valid_credentials": [],
            "success": False
        }

    results: List[CredentialResult] = []
    # Merged audit across whichever method(s) ran, in the order they ran.
    # kex_legacy_detected and fell_back_to_nmap are LABELS the UI reads
    # (dashboard/frontend/src/components/credentials/CredentialAuditPanel.tsx);
    # nothing selects a tool from them any more. audit["selection"] below is
    # where the actual decisions and their reasons are recorded.
    audit: Dict[str, Any] = {
        "credential_source": "cred_checker:default_credentials_dict",
        "users_tried":            sorted({u for u, _ in credentials if u}),
        "passwords_tried_masked": sorted({_mask_password(p) for _, p in credentials}),
        "credentials_tested":     len(credentials),
        "methods_used":           [],
        "method_audits":          [],   # list of per-method audit dicts
        "kex_legacy_detected":    False,
        "fell_back_to_nmap":      False,
    }

    learn = _tool_learning()

    if method in CRED_METHODS:
        # An explicit method is an operator instruction, so it is obeyed as
        # given — no reordering, no fallback. The attempt is still recorded, so
        # a forced run still teaches the platform something.
        results, m_audit = CRED_METHODS[method](target, port, service, credentials)
        audit["methods_used"].append(method)
        audit["method_audits"].append(m_audit)
        audit["kex_legacy_detected"] = bool(m_audit.get("kex_legacy_detected"))
        if learn:
            err = _method_error_text(m_audit)
            sig, phrase = learn.error_signature(err) if not results else (None, None)
            learn.record_attempt(
                method, service=service, target=target, port=port,
                success=bool(results), result_count=len(results),
                signature=sig, phrase=phrase, chosen_because="operator_forced")
    else:
        # Default behaviour: work through the authorised methods, learning from
        # each failure which one to reach for next.
        candidates = [m for m in DEFAULT_METHOD_ORDER if m in CRED_METHODS]
        store_ok = bool(learn) and learn.available()
        if learn and store_ok:
            candidates, notes = learn.preferred_order(candidates, service=service)
        else:
            notes = ["learning store unavailable; declared order used"] if learn \
                else ["etl/tool_learning not importable; declared order used"]

        selection: Dict[str, Any] = {
            "candidates": list(candidates),
            "learning_available": store_ok,   # NOT the same as "no rule matched"
            "notes": notes,
            "decisions": [],
            "learned": [],
        }
        audit["selection"] = selection

        sequence: List[Dict[str, Any]] = []
        remaining = list(candidates)
        tool: Optional[str] = remaining[0] if remaining else None
        reason, rule_id = "default_order", None

        while tool:
            t_results, t_audit = CRED_METHODS[tool](target, port, service, credentials)
            audit["methods_used"].append(tool)
            audit["method_audits"].append(t_audit)
            if t_audit.get("kex_legacy_detected"):
                audit["kex_legacy_detected"] = True

            ok = bool(t_results)
            sig = phrase = None
            if not ok and learn:
                sig, phrase = learn.error_signature(_method_error_text(t_audit))
            sequence.append({"tool": tool, "success": ok,
                             "result_count": len(t_results),
                             "signature": sig, "phrase": phrase})
            selection["decisions"].append({
                "tool": tool, "chosen_because": reason, "rule_id": rule_id,
                "valid_credentials": len(t_results),
                "failure_signature": sig, "failure_phrase": phrase,
            })
            if learn:
                learn.record_attempt(
                    tool, service=service, target=target, port=port,
                    success=ok, result_count=len(t_results),
                    signature=sig, phrase=phrase,
                    chosen_because=(f"learned:{rule_id}" if rule_id else reason))

            if ok:
                results = t_results
                break

            remaining.remove(tool)
            if not remaining:
                tool, reason, rule_id = None, "exhausted", None
                break
            if learn:
                tool, reason, rule_id = learn.next_tool(
                    tool, sig, remaining, service=service, store_available=store_ok)
            else:
                tool, reason, rule_id = remaining[0], "default_order", None
            if tool:
                logger.info(
                    f"[cred_checker] {service}://{target}:{port} {sequence[-1]['tool']} "
                    f"found nothing; trying {tool} ({reason})")

        selection["stopped_because"] = reason
        # Teach: within this run, a tool that failed with signature S followed by
        # one that succeeded IS the rule. Nothing to type.
        if learn:
            selection["learned"] = learn.observe_sequence(sequence, service=service)

        audit["fell_back_to_nmap"] = (
            len(audit["methods_used"]) > 1 and "nmap" in audit["methods_used"][1:])

    # Roll the per-attempt proof up to one place. The UI should not have to
    # walk method_audits[*].attempts[*] to answer "what makes you say this
    # password works" — that is the first question anyone asks of a credential
    # finding, and it belongs one level from the top.
    audit["evidence"] = [
        {
            "username": a.get("username"),
            "method": ma.get("method"),
            "output": a.get("evidence"),
            "command": a.get("command"),
        }
        for ma in audit["method_audits"]
        for a in ma.get("attempts", [])
        if a.get("success")
    ]

    # Human-readable summary for the audit panel. Built from what actually ran
    # rather than from a named pair of tools, so a new method needs no edit here
    # and the line never claims a fallback that did not happen.
    total_attempts = sum(
        len(ma.get("attempts", [])) for ma in audit["method_audits"]
    )
    chain = "\u2192".join(audit["methods_used"]) or "no method"
    summary = f"{len(results)} valid / {total_attempts} attempts via {chain}"
    sel = audit.get("selection") or {}
    learned_from = [d for d in sel.get("decisions", [])
                    if d.get("chosen_because") == "learned"]
    if learned_from:
        summary += f" ({learned_from[0]['tool']} chosen by a learned rule)"
    elif sel.get("stopped_because") == "learned_dead_end":
        summary += " (no further method: every fallback has failed this way before)"
    elif not sel.get("learning_available", True):
        summary += " (learning store unavailable \u2014 declared order used)"
    # The failure each method reported, in its own words. This used to be a
    # hardcoded sentence about SSH key exchange; it now shows whatever the tool
    # actually said, for any service.
    if not results:
        phrases = [d["failure_phrase"] for d in sel.get("decisions", [])
                   if d.get("failure_phrase")]
        if phrases:
            summary += " \u2014 " + "; ".join(dict.fromkeys(phrases))[:300]
    audit["summary"] = summary

    return {
        "service": service,
        "target": target,
        "port": port,
        "credentials_tested": len(credentials),
        "valid_credentials": [
            {
                "username": r.username,
                "password": r.password,
                "method": r.method,
                "details": r.details
            }
            for r in results
        ],
        "audit": audit,
        "success": len(results) > 0
    }


def check_all_default_credentials(
    target: str,
    ports: List[int] = None,
    services: List[str] = None
) -> Dict[str, Any]:
    """
    Check default credentials across multiple ports/services.

    Args:
        target: Target IP address
        ports: List of ports to check (auto-maps to services)
        services: List of specific services to check

    Returns:
        Consolidated results dictionary
    """
    results = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": [],
        "total_valid": 0,
        "services_checked": 0
    }

    # Build list of (port, service) tuples to check
    checks_to_run = []

    if ports:
        for port in ports:
            service = get_service_from_port(port)
            if service:
                checks_to_run.append((port, service))
            elif port == 1524:
                checks_to_run.append((port, "bindshell"))

    if services:
        for service in services:
            default_ports = SERVICE_PORTS.get(service, [])
            for port in default_ports:
                if (port, service) not in checks_to_run:
                    checks_to_run.append((port, service))

    # If nothing specified, check common auth services
    if not checks_to_run:
        common_services = ["ssh", "ftp", "telnet", "mysql", "postgres", "vnc"]
        for service in common_services:
            for port in SERVICE_PORTS.get(service, [])[:1]:  # First port only
                checks_to_run.append((port, service))

    # Run checks
    for port, service in checks_to_run:
        logger.info(f"Checking {service} on {target}:{port}")

        check_result = check_default_credentials(target, port, service)
        results["checks"].append(check_result)
        results["services_checked"] += 1

        if check_result.get("success"):
            results["total_valid"] += len(check_result.get("valid_credentials", []))

    return results


# Export functions for API use
__all__ = [
    "DEFAULT_CREDENTIALS",
    "SERVICE_PORTS",
    "check_default_credentials",
    "check_all_default_credentials",
    "check_bindshell",
    "check_vnc_password",
    "get_service_from_port",
    "CredentialResult",
]
