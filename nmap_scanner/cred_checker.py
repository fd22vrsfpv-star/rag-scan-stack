"""
Credential Testing Module
Tests default and weak credentials for common services.
"""

import os
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


def _classify_hydra_failure(output: str) -> Tuple[str, Optional[str]]:
    """Inspect hydra stdout+stderr to label why a single attempt failed.

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
                result = CredentialResult(
                    service=service,
                    target=target,
                    port=port,
                    username=username,
                    password=password if password else "(empty)",
                    success=True,
                    method="hydra",
                    details=output.strip()[:200]
                )
                results.append(result)
                attempt["success"] = True
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
                    result = CredentialResult(
                        service=service,
                        target=target,
                        port=port,
                        username=username,
                        password=password if password else "(empty)",
                        success=True,
                        method="nmap",
                        details=f"nmap {script}"
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


def check_default_credentials(
    target: str,
    port: int,
    service: str = None,
    method: str = "hydra"
) -> Dict[str, Any]:
    """
    Check default credentials for a service.

    Args:
        target: Target IP address
        port: Target port
        service: Service type (auto-detected from port if not provided)
        method: Testing method ('hydra' or 'nmap')

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
    # Merged audit across whichever method(s) ran.  Built up as the
    # method choices fan out (hydra-then-nmap-on-kex-fallback etc.).
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

    if method == "hydra":
        results, m_audit = check_credentials_hydra(target, port, service, credentials)
        audit["methods_used"].append("hydra")
        audit["method_audits"].append(m_audit)
        audit["kex_legacy_detected"] = bool(m_audit.get("kex_legacy_detected"))
    elif method == "nmap":
        results, m_audit = check_credentials_nmap(target, port, service, credentials)
        audit["methods_used"].append("nmap")
        audit["method_audits"].append(m_audit)
    else:
        # Default behaviour: try hydra first, fall back to nmap.  Also auto-
        # fall back to nmap when hydra detected SSH KEX-mismatch on every
        # attempt (the Metasploitable2 / legacy-OpenSSH case) -- nmap's
        # NSE brute scripts handle legacy KEX correctly where hydra/libssh
        # can't negotiate.  Record the fallback in the audit so operators
        # see *why* nmap was invoked.
        results, h_audit = check_credentials_hydra(target, port, service, credentials)
        audit["methods_used"].append("hydra")
        audit["method_audits"].append(h_audit)
        audit["kex_legacy_detected"] = bool(h_audit.get("kex_legacy_detected"))

        should_fallback = (
            not results
            and (h_audit.get("kex_legacy_detected") or
                 all((a.get("failure_mode") == "kex_mismatch")
                     for a in h_audit.get("attempts", [])
                     if not a.get("success")))
        )
        if not results and not should_fallback:
            # Plain "nothing worked" case -- still try nmap once
            should_fallback = True

        if should_fallback:
            logger.info(
                f"[cred_checker] {service}://{target}:{port} hydra returned "
                f"0 valid creds (kex_legacy_detected="
                f"{h_audit.get('kex_legacy_detected')}); falling back to nmap"
            )
            n_results, n_audit = check_credentials_nmap(target, port, service, credentials)
            audit["methods_used"].append("nmap")
            audit["method_audits"].append(n_audit)
            audit["fell_back_to_nmap"] = True
            if n_results:
                results = n_results

    # Human-readable summary for the audit panel.
    total_attempts = sum(
        len(ma.get("attempts", [])) for ma in audit["method_audits"]
    )
    if results:
        summary = f"{len(results)} valid / {total_attempts} attempts"
        if audit["fell_back_to_nmap"]:
            summary += " (hydra→nmap fallback)"
    elif audit["kex_legacy_detected"]:
        summary = (
            f"0 valid / {total_attempts} attempts — every hydra attempt "
            f"failed at SSH key exchange (target uses legacy ssh-rsa/dss)"
        )
        if audit["fell_back_to_nmap"]:
            summary += "; nmap fallback also found no valid creds"
    else:
        summary = f"0 valid / {total_attempts} attempts"
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
