"""
Common input validation utilities for RAG Scan Stack services.

This module provides secure validation functions to prevent:
- Path traversal attacks
- SQL injection
- Command injection
- SSRF attacks
"""

import re
import os
from pathlib import Path
from typing import Optional
import ipaddress


class ValidationError(ValueError):
    """Raised when input validation fails"""
    pass


def sanitize_scan_id(scan_id: str) -> str:
    """
    Sanitize scan ID to prevent path traversal and injection attacks.

    Only allows alphanumeric characters, hyphens, and underscores.

    Args:
        scan_id: The scan identifier to validate

    Returns:
        The sanitized scan_id

    Raises:
        ValidationError: If scan_id contains invalid characters

    Example:
        >>> sanitize_scan_id("abc-123_def")
        'abc-123_def'
        >>> sanitize_scan_id("../../etc/passwd")
        ValidationError: Invalid scan_id format
    """
    if not scan_id or not isinstance(scan_id, str):
        raise ValidationError("scan_id must be a non-empty string")

    if len(scan_id) > 255:
        raise ValidationError("scan_id too long (max 255 characters)")

    # Allow only alphanumeric, hyphens, and underscores
    if not re.match(r'^[a-zA-Z0-9_-]+$', scan_id):
        raise ValidationError(
            f"Invalid scan_id format: '{scan_id}'. "
            "Only alphanumeric, hyphens, and underscores allowed"
        )

    return scan_id


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal.

    Removes path separators and parent directory references.

    Args:
        filename: The filename to sanitize

    Returns:
        The sanitized filename (basename only)

    Raises:
        ValidationError: If filename is invalid

    Example:
        >>> sanitize_filename("report.xml")
        'report.xml'
        >>> sanitize_filename("../../etc/passwd")
        'passwd'
    """
    if not filename or not isinstance(filename, str):
        raise ValidationError("filename must be a non-empty string")

    if len(filename) > 255:
        raise ValidationError("filename too long (max 255 characters)")

    # Remove any path components, keep only the basename
    safe_name = os.path.basename(filename)

    # Additional check: ensure no null bytes or special chars
    if '\0' in safe_name or '\n' in safe_name or '\r' in safe_name:
        raise ValidationError("filename contains invalid characters")

    if safe_name in ('', '.', '..'):
        raise ValidationError("Invalid filename")

    return safe_name


def validate_output_path(base_dir: str, filename: str) -> str:
    """
    Validate that output path stays within the intended base directory.

    Prevents path traversal attacks by ensuring the resolved path
    is a subdirectory of base_dir.

    Args:
        base_dir: The base directory for outputs
        filename: The filename or relative path

    Returns:
        The validated absolute path

    Raises:
        ValidationError: If path escapes base_dir

    Example:
        >>> validate_output_path("/app/output", "scan.xml")
        '/app/output/scan.xml'
        >>> validate_output_path("/app/output", "../etc/passwd")
        ValidationError: Path traversal detected
    """
    # Ensure base_dir exists and is absolute
    base_path = Path(base_dir).resolve()

    # Sanitize filename first
    safe_filename = sanitize_filename(filename)

    # Construct the full path
    target_path = (base_path / safe_filename).resolve()

    # Verify the resolved path is within base_dir
    try:
        target_path.relative_to(base_path)
    except ValueError:
        raise ValidationError(
            f"Path traversal detected: '{filename}' escapes base directory"
        )

    return str(target_path)


def validate_scan_target(target: str, allow_private: bool = False) -> str:
    """
    Validate scan target to prevent SSRF attacks.

    Checks if the target is a valid IP or hostname and optionally
    blocks private/internal addresses.

    Args:
        target: IP address or hostname to validate
        allow_private: If False, reject private/internal IPs (default: False)

    Returns:
        The validated target

    Raises:
        ValidationError: If target is invalid or disallowed

    Example:
        >>> validate_scan_target("192.168.1.100", allow_private=True)
        '192.168.1.100'
        >>> validate_scan_target("169.254.169.254")  # AWS metadata
        ValidationError: Cannot scan private/internal IP addresses
    """
    if not target or not isinstance(target, str):
        raise ValidationError("target must be a non-empty string")

    if len(target) > 253:  # Max domain name length
        raise ValidationError("target too long")

    # Try to parse as IP address
    try:
        ip = ipaddress.ip_address(target)

        if not allow_private:
            # Block private, loopback, link-local, and multicast
            if (ip.is_private or ip.is_loopback or
                ip.is_link_local or ip.is_multicast):
                raise ValidationError(
                    f"Cannot scan private/internal IP addresses: {target}"
                )

            # Block AWS metadata endpoint
            if str(ip).startswith('169.254.169.254'):
                raise ValidationError(
                    "Cannot scan AWS metadata endpoint"
                )

        return str(ip)

    except ValidationError:
        raise  # re-raise our own errors (ValidationError is a ValueError subclass)
    except ValueError:
        pass

    # Not an IP — validate as domain name

    # Block localhost variants
    if not allow_private:
        localhost_variants = ['localhost', '0.0.0.0', '127.0.0.1']
        if target.lower() in localhost_variants or target.endswith('.local'):
            raise ValidationError(
                f"Cannot scan local domains: {target}"
            )

    # Validate domain name format (basic check)
    # Allow alphanumeric, hyphens, dots
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$', target):
        raise ValidationError(
            f"Invalid domain name format: {target}"
        )

    return target


def sanitize_port(port: int) -> int:
    """
    Validate port number is in valid range.

    Args:
        port: Port number to validate

    Returns:
        The validated port number

    Raises:
        ValidationError: If port is out of range
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid port: {port}")

    if not 1 <= port_int <= 65535:
        raise ValidationError(
            f"Port out of range: {port_int} (must be 1-65535)"
        )

    return port_int


def sanitize_command_arg(arg: str, allowed_chars: Optional[str] = None) -> str:
    """
    Sanitize command-line argument to prevent command injection.

    Args:
        arg: The argument to sanitize
        allowed_chars: Regex pattern of allowed characters (default: alphanumeric + common safe chars)

    Returns:
        The sanitized argument

    Raises:
        ValidationError: If argument contains disallowed characters
    """
    if not arg or not isinstance(arg, str):
        raise ValidationError("argument must be a non-empty string")

    if len(arg) > 1000:
        raise ValidationError("argument too long")

    # Default allowed characters: alphanumeric, dash, underscore, dot, comma, colon
    if allowed_chars is None:
        allowed_chars = r'^[a-zA-Z0-9._,:/-]+$'

    if not re.match(allowed_chars, arg):
        raise ValidationError(
            f"Invalid characters in argument: '{arg}'"
        )

    # Block common command injection patterns
    dangerous_patterns = [
        ';', '|', '&', '$', '`', '\n', '\r',
        '$(', '${', '&&', '||', '>>',
    ]

    for pattern in dangerous_patterns:
        if pattern in arg:
            raise ValidationError(
                f"Disallowed pattern in argument: '{pattern}'"
            )

    return arg


def validate_cidr(cidr: str) -> str:
    """
    Validate CIDR notation for network ranges.

    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")

    Returns:
        The validated CIDR string

    Raises:
        ValidationError: If CIDR is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR notation: {cidr} - {e}")


def sanitize_url_path(path: str) -> str:
    """
    Sanitize URL path component.

    Args:
        path: URL path for sanitization

    Returns:
        The sanitized path

    Raises:
        ValidationError: If path contains invalid characters
    """
    if not path or not isinstance(path, str):
        raise ValidationError("path must be a non-empty string")

    if len(path) > 2000:
        raise ValidationError("path too long")

    # Block path traversal attempts
    if '..' in path or '//' in path:
        raise ValidationError("Path traversal detected in URL path")

    # Allow URL-safe characters
    if not re.match(r'^[a-zA-Z0-9/_.-]+$', path):
        raise ValidationError(f"Invalid characters in URL path: '{path}'")

    return path


# Example usage and testing
if __name__ == "__main__":
    # Test scan_id validation
    try:
        assert sanitize_scan_id("abc-123_def") == "abc-123_def"
        print("✓ scan_id validation works")
    except AssertionError:
        print("✗ scan_id validation failed")

    try:
        sanitize_scan_id("../../etc/passwd")
        print("✗ Path traversal not blocked!")
    except ValidationError:
        print("✓ Path traversal blocked")

    # Test filename validation
    try:
        assert sanitize_filename("report.xml") == "report.xml"
        assert sanitize_filename("../../../etc/passwd") == "passwd"
        print("✓ Filename validation works")
    except AssertionError:
        print("✗ Filename validation failed")

    # Test target validation
    try:
        validate_scan_target("192.168.1.100", allow_private=True)
        print("✓ Private IP allowed when configured")
    except ValidationError:
        print("✗ Private IP validation failed")

    try:
        validate_scan_target("169.254.169.254")
        print("✗ AWS metadata endpoint not blocked!")
    except ValidationError:
        print("✓ AWS metadata endpoint blocked")
