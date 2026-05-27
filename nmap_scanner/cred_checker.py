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


def check_credentials_hydra(
    target: str,
    port: int,
    service: str,
    credentials: List[Tuple[str, str]],
    timeout: int = 60
) -> List[CredentialResult]:
    """
    Test credentials using Hydra.

    Args:
        target: Target IP address
        port: Target port
        service: Service type (ssh, ftp, mysql, etc.)
        credentials: List of (username, password) tuples
        timeout: Timeout in seconds

    Returns:
        List of successful credential results
    """
    results = []

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
        return results

    for username, password in credentials:
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
                logger.info(f"[+] Valid credentials found: {username}:{password} on {target}:{port} ({service})")

        except subprocess.TimeoutExpired:
            logger.warning(f"Hydra timeout for {username}@{target}:{port}")
        except Exception as e:
            logger.error(f"Hydra error: {e}")

    return results


def check_credentials_nmap(
    target: str,
    port: int,
    service: str,
    credentials: List[Tuple[str, str]],
    timeout: int = 120
) -> List[CredentialResult]:
    """
    Test credentials using nmap scripts.

    Args:
        target: Target IP address
        port: Target port
        service: Service type
        credentials: List of (username, password) tuples
        timeout: Timeout in seconds

    Returns:
        List of successful credential results
    """
    results = []

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
        return results

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

        # Parse output for valid credentials
        # Look for patterns like "Valid credentials" or service-specific success messages
        if "Valid credentials" in output or "Accounts:" in output:
            # Extract credentials from output
            import re

            # Common patterns in nmap brute output
            patterns = [
                r"(\S+):(\S*)\s+-\s+Valid",  # user:pass - Valid
                r"Accounts:.*?(\S+):(\S*)",   # Accounts: user:pass
            ]

            for pattern in patterns:
                matches = re.findall(pattern, output, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    username, password = match
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

    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap brute timeout for {target}:{port}")
    except Exception as e:
        logger.error(f"Nmap brute error: {e}")
    finally:
        # Cleanup temp files
        try:
            os.unlink(users_path)
            os.unlink(pass_path)
        except:
            pass

    return results


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

    results = []

    if method == "hydra":
        results = check_credentials_hydra(target, port, service, credentials)
    elif method == "nmap":
        results = check_credentials_nmap(target, port, service, credentials)
    else:
        # Try hydra first, fall back to nmap
        results = check_credentials_hydra(target, port, service, credentials)
        if not results:
            results = check_credentials_nmap(target, port, service, credentials)

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
