"""
Protocol mappings for Nuclei target generation.

This file maps service names and ports to URL schemes/protocols.
Edit this file to customize how services are scanned.
"""

# Common HTTP ports for scheme detection
HTTP_PORTS = {80, 8080, 8000, 8008, 3000, 5000, 8888}
HTTPS_PORTS = {443, 8443, 9443}

# Service name to protocol mappings for Nuclei targets
# These map Nmap service detection names to URL schemes
SERVICE_PROTOCOL_MAP = {
    # SSH
    'ssh': 'ssh',
    'openssh': 'ssh',
    # FTP
    'ftp': 'ftp',
    'ftp-data': 'ftp',
    'vsftpd': 'ftp',
    'proftpd': 'ftp',
    # Databases
    'mysql': 'mysql',
    'mariadb': 'mysql',
    'postgresql': 'postgres',
    'postgres': 'postgres',
    'mongodb': 'mongodb',
    'redis': 'redis',
    'memcached': 'memcached',
    'elasticsearch': 'http',  # ES uses HTTP
    'couchdb': 'http',
    'cassandra': 'cassandra',
    'mssql': 'mssql',
    'ms-sql-s': 'mssql',
    'oracle': 'oracle',
    'oracle-tns': 'oracle',
    # Mail
    'smtp': 'smtp',
    'smtps': 'smtps',
    'imap': 'imap',
    'imaps': 'imaps',
    'pop3': 'pop3',
    'pop3s': 'pop3s',
    # Directory/Auth
    'ldap': 'ldap',
    'ldaps': 'ldaps',
    'kerberos': 'kerberos',
    # Remote access
    'vnc': 'vnc',
    'rdp': 'rdp',
    'ms-wbt-server': 'rdp',
    'telnet': 'telnet',
    # Network services
    'dns': 'dns',
    'domain': 'dns',
    'snmp': 'snmp',
    'ntp': 'ntp',
    'tftp': 'tftp',
    # Message queues
    'amqp': 'amqp',
    'rabbitmq': 'amqp',
    'kafka': 'kafka',
    # Other
    'smb': 'smb',
    'microsoft-ds': 'smb',
    'netbios-ssn': 'smb',
    'docker': 'http',
    'kubernetes': 'https',
    # Web servers (explicit HTTP)
    'http': 'http',
    'https': 'https',
    'http-alt': 'http',
    'https-alt': 'https',
    'http-proxy': 'http',
    'nginx': 'http',
    'apache': 'http',
    'tomcat': 'http',
    'jetty': 'http',
    'iis': 'http',
}

# Port to protocol fallback (when service detection unavailable)
PORT_PROTOCOL_MAP = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    69: 'tftp',
    80: 'http',
    110: 'pop3',
    111: 'rpc',
    143: 'imap',
    161: 'snmp',
    389: 'ldap',
    443: 'https',
    445: 'smb',
    465: 'smtps',
    587: 'smtp',
    636: 'ldaps',
    993: 'imaps',
    995: 'pop3s',
    1433: 'mssql',
    1521: 'oracle',
    2049: 'nfs',
    2375: 'http',  # Docker HTTP
    2376: 'https',  # Docker HTTPS
    3000: 'http',
    3306: 'mysql',
    3389: 'rdp',
    5000: 'http',
    5432: 'postgres',
    5672: 'amqp',
    5900: 'vnc',
    5901: 'vnc',
    5902: 'vnc',
    6379: 'redis',
    8000: 'http',
    8008: 'http',
    8080: 'http',
    8443: 'https',
    8888: 'http',
    9200: 'http',  # Elasticsearch
    9300: 'http',  # Elasticsearch
    9443: 'https',
    11211: 'memcached',
    27017: 'mongodb',
}

# Protocols that should use URL format (scheme://host:port)
# NOTE: Nuclei only supports http/https URL schemes for templates.
# For non-HTTP services, templates expect host:port format.
URL_PROTOCOLS = {
    'http', 'https'
}


def get_protocol_for_service(service_name: str, port: int) -> str:
    """
    Determine the protocol for a service based on service name and port.

    Args:
        service_name: The detected service name (from Nmap), can be None
        port: The port number

    Returns:
        The protocol string (e.g., 'ssh', 'http', 'mysql')
    """
    service_lower = (service_name or "").lower().strip()

    # First, try exact match on service name
    if service_lower in SERVICE_PROTOCOL_MAP:
        return SERVICE_PROTOCOL_MAP[service_lower]

    # Check for partial matches in service name
    for svc_name, protocol in SERVICE_PROTOCOL_MAP.items():
        if svc_name in service_lower:
            return protocol

    # Fall back to port-based detection
    if port in PORT_PROTOCOL_MAP:
        return PORT_PROTOCOL_MAP[port]

    # Default to host:port format (no protocol prefix)
    return None


def build_target_url(ip: str, port: int, service_name: str = None) -> str:
    """
    Build a target URL/string for Nuclei based on service and port.

    Args:
        ip: The target IP address or hostname
        port: The port number
        service_name: The detected service name (optional)

    Returns:
        A target string like 'ssh://192.168.1.1:22' or '192.168.1.1:12345'
    """
    protocol = get_protocol_for_service(service_name, port)

    if protocol and protocol in URL_PROTOCOLS:
        return f"{protocol}://{ip}:{port}"
    else:
        # Unknown protocol - use host:port format
        return f"{ip}:{port}"
