"""
Tool Knowledge Base Loader
Loads and queries the service-to-tools YAML mappings for penetration testing recommendations.
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml

logger = logging.getLogger("tool_kb")


# =============================================================================
# High-Value Port Knowledge Base
# =============================================================================

# Ports commonly missed by 1-1000 scans but critical for exploitation
HIGH_VALUE_PORTS = {
    1099: {
        "service": "java-rmi",
        "vulns": ["CVE-2011-3556"],
        "msf": "exploit/multi/misc/java_rmi_server",
        "note": "Java RMI registry - common RCE vector"
    },
    1524: {
        "service": "bindshell",
        "vulns": ["backdoor"],
        "msf": None,
        "note": "Instant root shell - nc target 1524"
    },
    3306: {
        "service": "mysql",
        "vulns": ["weak-creds", "CVE-2012-2122"],
        "msf": "auxiliary/scanner/mysql/mysql_login",
        "note": "MySQL - test root with empty password"
    },
    3632: {
        "service": "distcc",
        "vulns": ["CVE-2004-2687"],
        "msf": "exploit/unix/misc/distcc_exec",
        "note": "DISTCC - unauthenticated RCE"
    },
    5432: {
        "service": "postgresql",
        "vulns": ["weak-creds"],
        "msf": "auxiliary/scanner/postgres/postgres_login",
        "note": "PostgreSQL - test postgres:postgres"
    },
    5900: {
        "service": "vnc",
        "vulns": ["weak-creds", "CVE-2006-2369"],
        "msf": "auxiliary/scanner/vnc/vnc_login",
        "note": "VNC - often password-only auth"
    },
    6667: {
        "service": "irc",
        "vulns": ["CVE-2010-2075"],
        "msf": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "note": "UnrealIRCd backdoor"
    },
    6697: {
        "service": "irc-ssl",
        "vulns": ["CVE-2010-2075"],
        "msf": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "note": "UnrealIRCd backdoor (SSL)"
    },
    8009: {
        "service": "ajp13",
        "vulns": ["CVE-2020-1938"],
        "msf": "auxiliary/admin/http/tomcat_ghostcat",
        "note": "Ghostcat - Tomcat AJP file read/RCE"
    },
    8180: {
        "service": "tomcat",
        "vulns": ["CVE-2009-3548", "weak-creds"],
        "msf": "exploit/multi/http/tomcat_mgr_deploy",
        "note": "Tomcat manager - test tomcat:tomcat"
    },
    8787: {
        "service": "drb",
        "vulns": ["CVE-2013-0156"],
        "msf": "exploit/linux/misc/drb_remote_codeexec",
        "note": "Ruby DRb RCE"
    },
}


# Known vulnerabilities for Metasploitable2 target
METASPLOITABLE2_VULNS = {
    "vsftpd": {
        "port": 21,
        "cve": "CVE-2011-2523",
        "msf": "exploit/unix/ftp/vsftpd_234_backdoor",
        "severity": "critical",
        "note": "Backdoor triggered by :) in username"
    },
    "samba_usermap": {
        "port": 445,
        "cve": "CVE-2007-2447",
        "msf": "exploit/multi/samba/usermap_script",
        "severity": "critical",
        "note": "Samba 3.0.20-3.0.25rc3 - username map script RCE"
    },
    "distcc": {
        "port": 3632,
        "cve": "CVE-2004-2687",
        "msf": "exploit/unix/misc/distcc_exec",
        "severity": "critical",
        "note": "Unauthenticated remote code execution"
    },
    "java_rmi": {
        "port": 1099,
        "cve": "CVE-2011-3556",
        "msf": "exploit/multi/misc/java_rmi_server",
        "severity": "critical",
        "note": "Java RMI Registry RCE"
    },
    "postgres": {
        "port": 5432,
        "cve": None,
        "default_creds": "postgres:postgres",
        "msf": "auxiliary/scanner/postgres/postgres_login",
        "severity": "high",
        "note": "Default credentials"
    },
    "mysql": {
        "port": 3306,
        "cve": None,
        "default_creds": "root:",
        "msf": "auxiliary/scanner/mysql/mysql_login",
        "severity": "high",
        "note": "Root with empty password"
    },
    "vnc": {
        "port": 5900,
        "cve": None,
        "default_creds": "password",
        "msf": "auxiliary/scanner/vnc/vnc_login",
        "severity": "high",
        "note": "Password-only auth, common passwords"
    },
    "tomcat": {
        "port": 8180,
        "cve": None,
        "default_creds": "tomcat:tomcat",
        "msf": "exploit/multi/http/tomcat_mgr_deploy",
        "severity": "high",
        "note": "Default manager credentials"
    },
    "bindshell": {
        "port": 1524,
        "cve": None,
        "msf": None,
        "severity": "critical",
        "note": "Instant root shell: nc target 1524"
    },
    "ircd_backdoor": {
        "port": 6667,
        "cve": "CVE-2010-2075",
        "msf": "exploit/unix/irc/unreal_ircd_3281_backdoor",
        "severity": "critical",
        "note": "UnrealIRCd 3.2.8.1 backdoor"
    },
    "php_cgi": {
        "port": 80,
        "cve": "CVE-2012-1823",
        "msf": "exploit/multi/http/php_cgi_arg_injection",
        "severity": "critical",
        "note": "PHP CGI argument injection RCE"
    },
    "ssh_msfadmin": {
        "port": 22,
        "cve": None,
        "default_creds": "msfadmin:msfadmin",
        "msf": "auxiliary/scanner/ssh/ssh_login",
        "severity": "high",
        "note": "Default msfadmin credentials"
    },
    "telnet_msfadmin": {
        "port": 23,
        "cve": None,
        "default_creds": "msfadmin:msfadmin",
        "msf": "auxiliary/scanner/telnet/telnet_login",
        "severity": "high",
        "note": "Default msfadmin credentials"
    },
    "nfs_no_root_squash": {
        "port": 2049,
        "cve": None,
        "msf": None,
        "severity": "high",
        "note": "NFS share with no_root_squash - privesc via SUID"
    },
    "rexec": {
        "port": 512,
        "cve": None,
        "default_creds": "msfadmin:msfadmin",
        "msf": "auxiliary/scanner/rservices/rexec_login",
        "severity": "medium",
        "note": "Remote exec with default credentials"
    },
    "rlogin": {
        "port": 513,
        "cve": None,
        "default_creds": "msfadmin:msfadmin",
        "msf": "auxiliary/scanner/rservices/rlogin_login",
        "severity": "medium",
        "note": "Remote login with default credentials"
    },
    "rsh": {
        "port": 514,
        "cve": None,
        "msf": "auxiliary/scanner/rservices/rsh_login",
        "severity": "medium",
        "note": "Remote shell - may allow passwordless access"
    },
    "drb": {
        "port": 8787,
        "cve": None,
        "msf": "exploit/linux/misc/drb_remote_codeexec",
        "severity": "critical",
        "note": "Ruby DRb service RCE"
    },
}


def get_high_value_port_info(port: int) -> Optional[Dict[str, Any]]:
    """Get vulnerability information for a high-value port."""
    return HIGH_VALUE_PORTS.get(port)


def get_msf2_vuln_info(vuln_name: str) -> Optional[Dict[str, Any]]:
    """Get Metasploitable2 vulnerability information by name."""
    return METASPLOITABLE2_VULNS.get(vuln_name)


def get_all_high_value_ports() -> List[int]:
    """Get list of all high-value ports that should be scanned."""
    return list(HIGH_VALUE_PORTS.keys())


def get_msf2_vulns_by_port(port: int) -> List[Dict[str, Any]]:
    """Get all known Metasploitable2 vulnerabilities for a given port."""
    results = []
    for name, info in METASPLOITABLE2_VULNS.items():
        if info.get("port") == port:
            results.append({"name": name, **info})
    return results


def get_critical_msf2_vulns() -> List[Dict[str, Any]]:
    """Get all critical severity Metasploitable2 vulnerabilities."""
    results = []
    for name, info in METASPLOITABLE2_VULNS.items():
        if info.get("severity") == "critical":
            results.append({"name": name, **info})
    return results

# Default path to the knowledge base
DEFAULT_KB_PATH = os.getenv("TOOL_KB_PATH", "/knowledge/service_tools.yaml")


# Service-name aliases for nmap output variants.
#
# nmap emits service strings that don't always match canonical KB keys --
# things like `ssl/http`, `http-proxy`, `microsoft-ds`, `domain`.  This map
# normalizes those variants so a port detected as "ssl/https-alt" hits the
# `https` KB entry rather than falling through to a generic banner grab.
#
# Add new entries here as new nmap service-name variants are observed in
# real scans.  Keep keys lowercase; values must reference an actual KB key
# in `knowledge/service_tools.yaml`.
_SERVICE_ALIASES: Dict[str, str] = {
    # HTTP family
    "http-proxy":     "http",
    "http-alt":       "http",
    "http-rpc-epmap": "http",
    "http-mgmt":      "http",
    "https-alt":      "https",
    "ssl/http":       "https",   # TLS-wrapped HTTP == HTTPS semantically
    "ssl/https":      "https",
    "ssl/http-alt":   "https",
    "ssl/http-proxy": "https",
    "ssl/http-mgmt":  "https",
    # SMB / Windows file-sharing
    "microsoft-ds":   "smb",
    "netbios-ssn":    "smb",
    "netbios-ns":     "smb",
    # DNS
    "domain":         "dns",
    "domain-s":       "dns",
    # SSH variants (some scanners emit banner-derived names)
    "openssh":        "ssh",
    "dropbear":       "ssh",
    # Database aliases
    "mariadb":        "mysql",
    "postgres":       "postgresql",
    "ms-sql-s":       "mssql",
    "ms-sql":         "mssql",
    "ssl/ms-sql-s":   "mssql",
    # RDP
    "ms-wbt-server":  "rdp",
    "ssl/ms-wbt-server": "rdp",
    # SMTP variants -- canonicalize to smtp; KB has tls coverage already
    "submission":     "smtp",   # port 587 (mail submission)
    "smtps":          "smtp",
    "ssl/smtp":       "smtp",
    "ssl/submission": "smtp",
    # POP3 / IMAP TLS variants
    "pop3s":          "pop3",
    "ssl/pop3":       "pop3",
    "imaps":          "imap",
    "ssl/imap":       "imap",
    # LDAP
    "ldaps":          "ldap",
    "ssl/ldap":       "ldap",
    # FTP
    "ftps":           "ftp",
    "ssl/ftp":        "ftp",
    "ftp-data":       "ftp",
    # VNC
    "vnc-http":       "vnc",
    # Kerberos
    "kerberos-sec":   "kerberos",
    # SNMP variants
    "snmptrap":       "snmp",
    # WinRM
    "wsmans":         "winrm",
    "ssl/wsmans":     "winrm",
    # Top-100 expansion (2026-06-07) - nmap variants for the new services
    "elastic":          "elasticsearch",
    "elasticsearch-tcp":"elasticsearch",
    "rabbitmq-amqp":    "rabbitmq",
    "amqp":             "rabbitmq",
    "amqps":            "rabbitmq",
    "ssl/amqp":         "rabbitmq",
    "mqtt-tls":         "mqtt",
    "ssl/mqtt":         "mqtt",
    "secure-mqtt":      "mqtt",
    "kafka-broker":     "kafka",
    "couchdb-https":    "couchdb",
    "ssl/couchdb":      "couchdb",
    "etcd-client":      "etcd",
    "etcd-server":      "etcd",
    "consul-http":      "consul",
    "consul-rpc":       "consul",
    "consul-dns":       "consul",
    "zk":               "zookeeper",
    "zk-client":        "zookeeper",
    "neo4j-http":       "neo4j",
    "neo4j-bolt":       "neo4j",
    "ssl/neo4j":        "neo4j",
    "influx":           "influxdb",
    "click-house":      "clickhouse",
    "ms-sql-browser":   "mssql_browser",
    "ms-sql-m":         "mssql_browser",
    "rpcbind":          "portmap",
    "sunrpc":           "portmap",
    "epmap":            "msrpc",
    "ms-rpc":           "msrpc",
    "dce-rpc":          "msrpc",
    "ntp-udp":          "ntp",
    "tftp-udp":         "tftp",
    "rsync-tcp":        "rsync",
    "syslog-udp":       "syslog",
    "syslog-tls":       "syslog",
    "ssl/syslog":       "syslog",
    "snmp-trap":        "snmptrap",
    "ipmi-rmcp":        "ipmi",
    "ipmi-udp":         "ipmi",
    "asf-rmcp":         "ipmi",
    "modbus-tcp":       "modbus",
    "bacnet-udp":       "bacnet",
    "enip":             "ethernetip",
    "ethernet-ip":      "ethernetip",
    "coap-udp":         "coap",
    "secure-coap":      "coap",
    "ssl/coap":         "coap",
    "sip-tls":          "sip",
    "sips":             "sip",
    "ssl/sip":          "sip",
    "h.323":            "h323",
    "h323-q931":        "h323",
    "ipp":              "ipp",    # canonical (kept for clarity)
    "cups":             "ipp",
    "ipps":             "ipp",
    "printer":          "lpd",
    "afp-over-tcp":     "afp",
    "afpovertcp":       "afp",
    "iscsi-target":     "iscsi",
    "vmware-auth":      "vmware_esxi",
    "vmware-vsphere":   "vmware_esxi",
    "esxi":             "vmware_esxi",
    "vcenter":          "vmware_esxi",
    "ssl/vmware-auth":  "vmware_esxi",
    "squid-http":       "squid",
    "http-proxy-squid": "squid",
    "x11-1":            "x11",
    "x11-2":            "x11",
    "x11-3":            "x11",
    "bonjour":          "mdns",
    "avahi":            "mdns",
    "llmnr":            "mdns",
    "domain-mdns":      "mdns",
    "ssl/nntp":         "nntp",
    "nntps":            "nntp",
    "submission-ssl":   "smtp",  # already smtp via existing entries, keep for clarity
    "ms-wbt":           "rdp",   # short form sometimes seen
}


def _normalize_service_name(name: str) -> str:
    """Map a service-name variant to its canonical KB key.

    Returns the alias's target if `name` is in `_SERVICE_ALIASES`;
    otherwise returns `name` lowercased.  Used by `get_service_info` to
    canonicalize nmap output before the substring-fallback lookup.

    Examples:
        _normalize_service_name("ssl/http")    -> "https"
        _normalize_service_name("http-proxy")  -> "http"
        _normalize_service_name("microsoft-ds") -> "smb"
        _normalize_service_name("ssh")         -> "ssh"
        _normalize_service_name("WeirdService") -> "weirdservice"
    """
    if not name:
        return name
    s = name.lower().strip()
    if s in _SERVICE_ALIASES:
        return _SERVICE_ALIASES[s]
    return s


class ToolKnowledgeBase:
    """
    Loads and queries the service-to-tools knowledge base.
    Provides fast lookups by service name or port number.
    """

    def __init__(self, kb_path: str = DEFAULT_KB_PATH):
        self.kb_path = kb_path
        self._data: Dict[str, Any] = {}
        self._port_to_service: Dict[int, str] = {}
        self._loaded = False
        self._load()

    def _load(self) -> bool:
        """Load the YAML knowledge base file."""
        try:
            path = Path(self.kb_path)
            if not path.is_file():
                logger.warning(f"[tool_kb] Knowledge base not found: {self.kb_path}")
                return False

            with open(path, "r", encoding="utf-8") as f:
                self._data = yaml.safe_load(f) or {}

            # Build port-to-service index
            self._build_port_index()
            self._loaded = True

            services_count = len(self._data.get("services", {}))
            ports_count = len(self._port_to_service)
            logger.info(f"[tool_kb] Loaded {services_count} services, {ports_count} port mappings")
            return True

        except Exception as e:
            logger.error(f"[tool_kb] Failed to load knowledge base: {e}")
            return False

    def _build_port_index(self):
        """Build reverse index from port to service name."""
        self._port_to_service = {}

        # From services section
        services = self._data.get("services", {})
        for service_name, service_data in services.items():
            ports = service_data.get("ports", [])
            for port in ports:
                self._port_to_service[int(port)] = service_name

        # From port_hints section (fallback mappings)
        port_hints = self._data.get("port_hints", {})
        for port, service_name in port_hints.items():
            # Don't override if already mapped from services
            if int(port) not in self._port_to_service:
                self._port_to_service[int(port)] = service_name

    def reload(self) -> bool:
        """Reload the knowledge base from disk."""
        return self._load()

    def is_loaded(self) -> bool:
        """Check if knowledge base is loaded."""
        return self._loaded

    def get_service_by_port(self, port: int) -> Optional[str]:
        """
        Get service name for a given port number.

        Args:
            port: Port number

        Returns:
            Service name or None if not found
        """
        return self._port_to_service.get(port)

    def resolve_service_name(self, service_name: str) -> Optional[str]:
        """Return the canonical KB key for a (possibly aliased) service name.

        Returns None if the input doesn't resolve to any KB entry.  Used by
        `get_tools_for_service` so the result's `service` field reflects the
        resolved key (e.g. input "amqp" -> "rabbitmq") rather than echoing
        the operator's input -- otherwise downstream consumers can't tell
        whether alias resolution happened.
        """
        if not service_name:
            return None
        services = self._data.get("services", {})
        s = service_name.lower().strip()
        # 1. Exact
        if s in services:
            return s
        # 2. Alias
        normalized = _normalize_service_name(s)
        if normalized != s and normalized in services:
            return normalized
        # 3. ssl/tls strip
        if s.startswith(("ssl/", "tls/")):
            inner = s.split("/", 1)[1]
            if inner in services:
                return inner
            inner_normalized = _normalize_service_name(inner)
            if inner_normalized in services:
                return inner_normalized
        # 4. Longest substring match -- mirrors the partial-match branch
        #    in get_service_info so callers see the same canonical key.
        matches = [name for name in services if s in name or name in s]
        if matches:
            matches.sort(key=lambda x: -len(x))
            return matches[0]
        return None

    def get_service_info(self, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Get full service information by name.

        Resolution order:
          1. Exact lowercase match (e.g. "http" → http entry).
          2. Alias map (nmap variants like "ssl/http", "http-proxy",
             "microsoft-ds", "domain" → canonical KB key).
          3. ssl/tls prefix strip + recheck (so "ssl/<anything>" still
             routes to the wrapped service, tagged as TLS via the alias
             map for http/https).
          4. Longest-substring partial match (so "ssl/https-alt" hits
             `https` instead of getting swallowed by `http` due to YAML
             ordering).

        Args:
            service_name: Service name as emitted by nmap or the
                operator (e.g., 'ssh', 'http', 'ssl/https-alt',
                'microsoft-ds').

        Returns:
            Service info dict or None if no match.
        """
        if not service_name:
            return None

        services = self._data.get("services", {})
        service_name_lower = service_name.lower().strip()

        # 1. Exact match
        if service_name_lower in services:
            return services[service_name_lower]

        # 2. Alias map (catches the bulk of nmap's variant strings)
        normalized = _normalize_service_name(service_name_lower)
        if normalized != service_name_lower and normalized in services:
            return services[normalized]

        # 3. Strip ssl/tls wrapper if present and recheck (covers
        #    `ssl/<service>` where <service> is a direct KB key but not
        #    in the alias map -- e.g. `ssl/mysql`).
        if service_name_lower.startswith(("ssl/", "tls/")):
            inner = service_name_lower.split("/", 1)[1]
            if inner in services:
                return services[inner]
            inner_normalized = _normalize_service_name(inner)
            if inner_normalized in services:
                return services[inner_normalized]

        # 4. Longest-substring partial match -- prefer the more specific
        #    match.  Without the length sort, "https-alt" gets swallowed
        #    by `http` because YAML key order puts `http` before
        #    `https`.
        matches: List[tuple] = []
        for name, data in services.items():
            if service_name_lower in name or name in service_name_lower:
                matches.append((name, data))
        if matches:
            matches.sort(key=lambda x: -len(x[0]))
            return matches[0][1]

        return None

    def get_tools_for_service(
        self,
        service: str = None,
        port: int = None,
        include_msf: bool = True,
        include_nuclei: bool = True
    ) -> Dict[str, Any]:
        """
        Get tool recommendations for a service or port.

        Args:
            service: Service name (e.g., 'ssh', 'http')
            port: Port number (used to infer service if service not provided)
            include_msf: Include Metasploit modules
            include_nuclei: Include Nuclei tags

        Returns:
            Dictionary with tool recommendations
        """
        # Resolve service name from port if not provided
        if not service and port:
            service = self.get_service_by_port(port)

        if not service:
            return {
                "error": "Service not specified and could not be inferred from port",
                "port": port,
                "tools": [],
                "metasploit": [],
                "nuclei_tags": []
            }

        service_info = self.get_service_info(service)

        if not service_info:
            return {
                "error": f"Unknown service: {service}",
                "service": service,
                "port": port,
                "tools": [],
                "metasploit": [],
                "nuclei_tags": []
            }

        # Surface the canonical KB key (post-alias) so consumers can tell
        # whether alias resolution happened.  `input_service` preserves the
        # operator's original string for debugging / audit.
        canonical = self.resolve_service_name(service) or service.lower()
        result = {
            "service": canonical,
            "input_service": service.lower(),
            "description": service_info.get("description", ""),
            "common_ports": service_info.get("ports", []),
            "tools": service_info.get("tools", []),
            "common_vulns": service_info.get("common_vulns", [])
        }

        if include_msf:
            result["metasploit"] = service_info.get("metasploit", [])

        if include_nuclei:
            result["nuclei_tags"] = service_info.get("nuclei_tags", [])

        # Fill in target/port placeholders in commands
        if port:
            result["port_used"] = port
            result["tools"] = self._format_commands(result["tools"], port=port)

        return result

    def get_tech_signatures(self) -> Dict[str, Any]:
        """Return the `tech_signatures` map from the KB (G1).

        Maps a detected web technology (CMS/framework) to the nuclei tags
        worth running against it.  Empty dict if the KB has no such section.
        """
        return self._data.get("tech_signatures", {}) or {}

    def match_tech_to_tags(self, tech_tokens: List[str]) -> List[Dict[str, Any]]:
        """Match detected tech tokens to tech_signatures entries (G1).

        Each token (e.g. "WordPress 5.9", "Apache/2.4.41") is compared
        case-insensitively against every signature's `match:` substrings.
        Returns a deduped list of {name, nuclei_tags, note} for each
        signature that matched at least one token.

        Args:
            tech_tokens: detected technology strings from httpx/whatweb
                         (recon_findings.data->'tech' + ->>'webserver').
        """
        if not tech_tokens:
            return []
        haystack = [t.lower() for t in tech_tokens if t]
        matched: List[Dict[str, Any]] = []
        seen = set()
        for name, sig in self.get_tech_signatures().items():
            if name in seen:
                continue
            patterns = [p.lower() for p in (sig.get("match") or [])]
            if any(p in tok for p in patterns for tok in haystack):
                matched.append({
                    "name": name,
                    "nuclei_tags": sig.get("nuclei_tags", []),
                    "note": sig.get("note", ""),
                })
                seen.add(name)
        return matched

    def _format_commands(
        self,
        tools: List[Dict[str, Any]],
        target: str = "{target}",
        port: int = None
    ) -> List[Dict[str, Any]]:
        """
        Format command templates with actual values.

        Args:
            tools: List of tool dictionaries
            target: Target IP/hostname
            port: Port number

        Returns:
            Tools list with formatted commands
        """
        formatted = []
        for tool in tools:
            tool_copy = dict(tool)
            if "command" in tool_copy and port:
                tool_copy["command"] = tool_copy["command"].replace("{port}", str(port))
            formatted.append(tool_copy)
        return formatted

    def get_all_services(self) -> List[str]:
        """Get list of all known service names."""
        return list(self._data.get("services", {}).keys())

    def get_tool_metadata(self) -> Dict[str, Any]:
        """Return the tool_metadata block (per-tool classification + overlap
        groups). Empty dict if the KB has none."""
        return dict(self._data.get("tool_metadata", {}) or {})

    def get_non_scanner_tools(self) -> set:
        """Tool names classified as non-scanners (e.g. cve_lookup) — these must
        NOT be emitted as per-service scan recommendations."""
        meta = self.get_tool_metadata().get("tools", {}) or {}
        return {
            name.lower()
            for name, spec in meta.items()
            if (spec or {}).get("type") == "cve_lookup" or (spec or {}).get("active") is False
        }

    def get_overlap_groups(self) -> Dict[str, Any]:
        """Return overlap_groups {group: {description, members[]}}."""
        return dict(self.get_tool_metadata().get("overlap_groups", {}) or {})

    def get_all_port_mappings(self) -> Dict[int, str]:
        """Get all port-to-service mappings."""
        return dict(self._port_to_service)

    def search_tools(
        self,
        query: str,
        tool_type: str = None
    ) -> List[Dict[str, Any]]:
        """
        Search for tools by name or purpose.

        Args:
            query: Search query
            tool_type: Filter by type ('tools', 'metasploit', or None for all)

        Returns:
            List of matching tools with service context
        """
        results = []
        query_lower = query.lower()

        services = self._data.get("services", {})
        for service_name, service_data in services.items():
            # Search in tools
            if tool_type in (None, "tools"):
                for tool in service_data.get("tools", []):
                    name = tool.get("name", "").lower()
                    purpose = tool.get("purpose", "").lower()
                    if query_lower in name or query_lower in purpose:
                        results.append({
                            "service": service_name,
                            "type": "tool",
                            **tool
                        })

            # Search in Metasploit modules
            if tool_type in (None, "metasploit"):
                for msf in service_data.get("metasploit", []):
                    module = msf.get("module", "").lower()
                    purpose = msf.get("purpose", "").lower()
                    if query_lower in module or query_lower in purpose:
                        results.append({
                            "service": service_name,
                            "type": "metasploit",
                            **msf
                        })

        return results


# Global instance
_kb_instance: Optional[ToolKnowledgeBase] = None


def get_tool_kb() -> ToolKnowledgeBase:
    """Get or create the global ToolKnowledgeBase instance."""
    global _kb_instance
    if _kb_instance is None:
        _kb_instance = ToolKnowledgeBase()
    return _kb_instance


def recommend_tools(
    service: str = None,
    port: int = None,
    include_msf: bool = True,
    include_nuclei: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to get tool recommendations.

    Args:
        service: Service name (e.g., 'ssh', 'http')
        port: Port number
        include_msf: Include Metasploit modules
        include_nuclei: Include Nuclei tags

    Returns:
        Tool recommendations dictionary
    """
    kb = get_tool_kb()
    return kb.get_tools_for_service(
        service=service,
        port=port,
        include_msf=include_msf,
        include_nuclei=include_nuclei
    )
