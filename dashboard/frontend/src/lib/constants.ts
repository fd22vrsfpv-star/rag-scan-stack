export const BUILD_VERSION = '2026.06.09-02'
export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info', 'recon', 'error'] as const
export type Severity = (typeof SEVERITY_LEVELS)[number]

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#facc15',
  low: '#2563eb',
  info: '#6b7280',
  error: '#991b1b',
  recon: '#0891b2',
}

export const SEVERITY_BG: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-blue-600 text-white',
  info: 'bg-gray-500 text-white',
  error: 'bg-red-900 text-white',
  recon: 'bg-cyan-600 text-white',
}

// Scan tool metadata: proxy support, touches target, passive/active, remote exec support
// proxy: true = supports SOCKS proxy routing through nodes
// touchesTarget: true = sends packets/requests directly to the target
// passive: true = queries third-party APIs/databases only, never contacts the target
// remote: true = can run on a remote node (via SOCKS proxy or SSH remote exec push)
export type ScanMeta = { id: string; label: string; desc: string; icon: string; proxy?: boolean; touchesTarget?: boolean; passive?: boolean; remote?: boolean }

export const NUCLEI_TAG_PRESETS = [
  { id: 'quick-recon',   label: 'Quick Recon',      tags: 'tech,panel,exposure,ssl,header,cors,dns',                                                      desc: 'Fast non-intrusive recon (tech stack, panels, SSL, headers)' },
  { id: 'config-audit',  label: 'Config Audit',     tags: 'misconfig,default-login,disclosure,unauth,debug,backup,git',                                   desc: 'Misconfigurations, default creds, exposed debug/backup files' },
  { id: 'cloud-posture',label: 'Cloud Posture',     tags: 'cloud,aws,azure,token',                                                                        desc: 'Cloud misconfigs, exposed S3/Azure, leaked tokens' },
  { id: 'web-vulns',     label: 'Web Vulnerabilities', tags: 'xss,sqli,ssrf,lfi,rfi,rce,auth-bypass',                                                     desc: 'Active web vulnerability detection (XSS, SQLi, SSRF, RCE)' },
  { id: 'takeover',      label: 'Takeover & Redirect', tags: 'takeover,redirect',                                                                         desc: 'Subdomain takeover + open redirects' },
  { id: 'full-recon',    label: 'Full Assessment',  tags: 'exposure,misconfig,tech,panel,default-login,token,disclosure,unauth,ssl,cors,header,redirect,takeover,dns,cloud,debug,backup,git', desc: 'Comprehensive — all recon + config + cloud tags' },
] as const

export const SCAN_CATEGORIES: { name: string; desc: string; scans: ScanMeta[] }[] = [
  {
    name: 'Port Scanning',
    desc: 'Discover open ports and services',
    scans: [
      { id: 'masscan', label: 'Masscan', desc: 'Fast SYN port discovery', icon: 'Zap', proxy: false, touchesTarget: true, passive: false, remote: true },
      { id: 'nmap', label: 'Nmap Pipeline', desc: 'Masscan discovery + Nmap service detection', icon: 'Search', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'nmap-tcp', label: 'Nmap Standalone', desc: 'TCP connect scan (SOCKS proxy compatible)', icon: 'Search', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'full', label: 'Full Port Scan', desc: 'Complete 1-65535 pipeline', icon: 'ScanLine', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'udp', label: 'UDP Scan', desc: 'Common UDP ports', icon: 'Radio', proxy: false, touchesTarget: true, passive: false, remote: true },
      { id: 'naabu', label: 'Naabu', desc: 'Alternative port scanner', icon: 'Radar', proxy: true, touchesTarget: true, passive: false, remote: true },
    ],
  },
  {
    name: 'Recon',
    desc: 'Enumerate subdomains, DNS, and services',
    scans: [
      { id: 'subfinder', label: 'Subfinder', desc: 'Subdomain enumeration', icon: 'Network', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'amass', label: 'Amass', desc: 'Advanced subdomain enumeration', icon: 'Network', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'dnsx', label: 'dnsx', desc: 'DNS resolution', icon: 'Globe2', proxy: false, touchesTarget: true, passive: false, remote: false },
      { id: 'httpx', label: 'httpx', desc: 'HTTP probe + tech detect', icon: 'Server', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'tlsx', label: 'TLSX', desc: 'TLS certificate analysis', icon: 'Lock', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'gau', label: 'GAU', desc: 'Historical URL discovery', icon: 'Globe2', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'waybackurls', label: 'Waybackurls', desc: 'Wayback Machine URLs', icon: 'Globe2', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'uncover', label: 'Uncover', desc: 'Shodan/Censys/Fofa search', icon: 'Search', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'chaos', label: 'Chaos', desc: 'PD passive subdomain DB', icon: 'Globe2', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'shuffledns', label: 'ShuffleDNS', desc: 'Active DNS bruteforce', icon: 'Network', proxy: false, touchesTarget: true, passive: false, remote: false },
      { id: 'recon-pipeline', label: 'Recon Pipeline', desc: 'Full chain: subfinder+chaos\u2192alterx\u2192shuffledns\u2192dnsx\u2192crtsh\u2192censys\u2192asnmap\u2192httpx\u2192tlsx\u2192whatweb', icon: 'Layers', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'crtsh', label: 'crt.sh', desc: 'CT log certificate search', icon: 'ShieldCheck', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'whatweb', label: 'WhatWeb', desc: 'Web technology fingerprinting', icon: 'Search', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'trufflehog', label: 'TruffleHog', desc: 'Secret scanning (git/github/fs)', icon: 'ShieldAlert', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'censys', label: 'Censys', desc: 'Search hosts, certs & subdomains', icon: 'Search', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'gowitness', label: 'GoWitness', desc: 'Website screenshot capture', icon: 'Monitor', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'whois', label: 'WHOIS', desc: 'Domain/IP registration, org, netblock, ASN lookup', icon: 'FileText', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'wafw00f', label: 'wafw00f', desc: 'WAF detection & fingerprinting', icon: 'Shield', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'greyhatwarfare', label: 'GreyHatWarfare', desc: 'Exposed S3 buckets & cloud files', icon: 'Cloud', proxy: false, touchesTarget: false, passive: true, remote: false },
      { id: 'passive-recon', label: 'Passive Recon', desc: 'Passive-only recon with cert chain discovery', icon: 'ShieldCheck', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'subzy', label: 'Subzy', desc: 'Subdomain takeover detection (dangling CNAME)', icon: 'ShieldAlert', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'subdomain-takeover', label: 'Subdomain Takeover', desc: 'Comprehensive subdomain takeover detection (AWS S3, Azure, GitHub Pages, etc.)', icon: 'ShieldAlert', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'golinkfinder', label: 'GoLinkFinder', desc: 'Extract API endpoints from JavaScript files', icon: 'FileCode', proxy: true, touchesTarget: true, passive: false, remote: true },
    ],
  },
  {
    name: 'Service Enum',
    desc: 'Service-specific infrastructure enumeration',
    scans: [
      { id: 'service-enum', label: 'Full Service Enum', desc: 'Email + DNS infrastructure audit (SPF/DKIM/DMARC, MX, zone transfer, NS fingerprint)', icon: 'Server', proxy: false, touchesTarget: true, passive: false, remote: true },
      { id: 'email-enum', label: 'Email Infrastructure', desc: 'SPF/DKIM/DMARC validation, MX server enumeration, provider detection', icon: 'Mail', proxy: false, touchesTarget: true, passive: false, remote: true },
      { id: 'dns-enum', label: 'DNS Infrastructure', desc: 'All record types, zone transfer (AXFR), nameserver fingerprint, reverse DNS', icon: 'Network', proxy: false, touchesTarget: true, passive: false, remote: true },
    ],
  },
  {
    name: 'Web',
    desc: 'Web application scanning and crawling',
    scans: [
      { id: 'web', label: 'Web Scan', desc: 'Gobuster + ZAP', icon: 'Globe', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'gobuster', label: 'Gobuster', desc: 'Directory & file brute-force', icon: 'FolderSearch', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'content-recon', label: 'Content Recon', desc: 'Spider, PDF/EXIF extract, wordlist gen, screenshots, content intel', icon: 'ScanSearch', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'pipeline', label: 'Web Pipeline', desc: 'wafw00f→Katana→Playwright→Gobuster→Nikto→Nuclei→ZAP', icon: 'Layers', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'katana', label: 'Katana', desc: 'Web crawler', icon: 'Sword', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'ffuf', label: 'ffuf', desc: 'Web fuzzer (dir/param/vhost)', icon: 'Zap', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'playwright', label: 'Playwright', desc: 'Browser-based scanning', icon: 'Monitor', proxy: false, touchesTarget: true, passive: false, remote: true },
      { id: 'whois', label: 'WHOIS', desc: 'Domain/IP registration, org, netblock, ASN lookup', icon: 'FileText', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'wafw00f', label: 'wafw00f', desc: 'WAF detection & fingerprinting', icon: 'Shield', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'burp-scan', label: 'Burp Suite', desc: 'Active scan via Burp Pro REST API (headless)', icon: 'Shield', proxy: true, touchesTarget: true, passive: false, remote: false },
    ],
  },
  {
    name: 'Vuln',
    desc: 'Vulnerability scanning and assessment',
    scans: [
      { id: 'nuclei', label: 'Nuclei', desc: 'Vulnerability templates', icon: 'Bug', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'nikto', label: 'Nikto', desc: 'Web server vulnerability scanner', icon: 'ShieldAlert', proxy: true, touchesTarget: true, passive: false, remote: true },
      { id: 'vulnx', label: 'VulnX', desc: 'CVE lookup by product/version/banner', icon: 'Bug', proxy: false, touchesTarget: false, passive: true, remote: false },
      { id: 'vulnx-scope', label: 'VulnX Scope Scan', desc: 'CVE lookup for all detected software in scope', icon: 'Bug', proxy: false, touchesTarget: false, passive: true, remote: false },
    ],
  },
  {
    name: 'Credentials',
    desc: 'Password attacks and credential testing',
    scans: [
      { id: 'brutus', label: 'Brutus', desc: 'Multi-protocol credential testing', icon: 'KeyRound', proxy: false, touchesTarget: true, passive: false, remote: true },
      { id: 'hashcat', label: 'Hashcat', desc: 'Hash cracking (NTLM/Kerberos/MD5)', icon: 'KeyRound', proxy: false, touchesTarget: false, passive: true, remote: false },
    ],
  },
  {
    name: 'AD / Internal',
    desc: 'Active Directory and internal network tools',
    scans: [
      { id: 'netexec', label: 'NetExec', desc: 'AD/SMB/LDAP credential testing', icon: 'Server', proxy: false, touchesTarget: true, passive: false, remote: false },
      { id: 'impacket', label: 'Impacket', desc: 'AD exploitation (secretsdump/psexec)', icon: 'Server', proxy: false, touchesTarget: true, passive: false, remote: false },
    ],
  },
  {
    name: 'Cloud',
    desc: 'Live cloud recon + import cloud security tool output',
    scans: [
      { id: 'cloud-tenant', label: 'Cloud Tenant ID', desc: 'Resolve Azure tenant GUID + federation type and AWS hosting indicators for a single domain', icon: 'Cloud', proxy: true, touchesTarget: false, passive: true, remote: true },
      { id: 'prowler-import', label: 'Prowler', desc: 'AWS/Azure/GCP posture', icon: 'Cloud' },
      { id: 'scoutsuite-import', label: 'ScoutSuite', desc: 'Multi-cloud audit', icon: 'Cloud' },
      { id: 'pacu-import', label: 'Pacu', desc: 'AWS exploitation framework', icon: 'Cloud' },
      { id: 'cloudfox-import', label: 'CloudFox', desc: 'Cloud privesc enumeration', icon: 'Cloud' },
      { id: 'azurehound-import', label: 'AzureHound', desc: 'Azure AD attack paths', icon: 'Cloud' },
      { id: 'microburst-import', label: 'MicroBurst', desc: 'NetSPI Azure AD enum (zip)', icon: 'Cloud' },
    ],
  },
]

// Flat list for backwards compatibility
export const SCAN_TYPES = SCAN_CATEGORIES.flatMap(c => c.scans)

export const SOURCES = ['nmap', 'nuclei', 'zap', 'gobuster', 'playwright', 'httpx', 'katana', 'nikto', 'subfinder', 'whatweb', 'amass', 'gau', 'waybackurls', 'trufflehog', 'ffuf', 'netexec', 'impacket', 'hashcat', 'censys', 'gowitness', 'whois', 'wafw00f', 'greyhatwarfare', 'subdomain-takeover', 'prowler', 'scoutsuite', 'pacu', 'cloudfox', 'azurehound', 'microburst', 'ssh-audit', 'sslscan', 'testssl', 'sslyze', 'vulscan', 'vulners', 'masscan', 'burpsuite'] as const

// AD Attack types for Sliver nodes (categorized)
export const AD_ATTACK_TYPES = [
  {
    category: 'Enumeration',
    attacks: [
      { id: 'bloodhound', label: 'BloodHound', desc: 'Map AD relationships (SharpHound)', tool: 'SharpHound.exe' },
      { id: 'seatbelt', label: 'Seatbelt', desc: 'Host security audit', tool: 'Seatbelt.exe' },
      { id: 'enum_domain', label: 'Enum Domain', desc: 'Domain controller enumeration', tool: 'SharpView.exe' },
    ],
  },
  {
    category: 'Credential Attacks',
    attacks: [
      { id: 'kerberoast', label: 'Kerberoast', desc: 'Extract TGS tickets for cracking', tool: 'Rubeus.exe' },
      { id: 'asreproast', label: 'AS-REP Roast', desc: 'Find accounts without pre-auth', tool: 'Rubeus.exe' },
      { id: 'dcsync', label: 'DCSync', desc: 'Extract hashes via DC replication', tool: 'Mimikatz.exe' },
    ],
  },
  {
    category: 'Lateral Movement',
    attacks: [
      { id: 'pth', label: 'Pass-the-Hash', desc: 'Lateral movement via NTLM hash', tool: 'Mimikatz.exe' },
    ],
  },
] as const

// Node status colors
export const NODE_STATUS_COLORS: Record<string, string> = {
  online: 'bg-green-500',
  offline: 'bg-red-500',
  degraded: 'bg-yellow-500',
  provisioning: 'bg-blue-500',
  connecting: 'bg-cyan-500',
  error: 'bg-orange-500',
}

export const SECRET_TYPES = [
  { value: 'password', label: 'Password' },
  { value: 'aws_key', label: 'AWS Key' },
  { value: 'aws_access_key', label: 'AWS Access Key' },
  { value: 'aws_sts', label: 'AWS STS Token' },
  { value: 'azure_key', label: 'Azure Key' },
  { value: 'azure_oauth', label: 'Azure OAuth Token' },
  { value: 'azure_sp', label: 'Azure Service Principal' },
  { value: 'gcp_sa_key', label: 'GCP Service Account Key' },
  { value: 'ssh_key', label: 'SSH Key' },
  { value: 'api_token', label: 'API Token' },
  { value: 'ntlm_hash', label: 'NTLM Hash' },
  { value: 'certificate', label: 'Certificate' },
  { value: 'other', label: 'Other' },
] as const

export const BRUTUS_PROTOCOLS = [
  'ssh', 'ftp', 'telnet', 'vnc', 'smb', 'ldap', 'winrm',
  'mysql', 'postgresql', 'mssql', 'mongodb', 'redis',
  'http', 'https', 'smtp', 'imap', 'pop3', 'snmp',
] as const

// ── Finding / Screenshot Tags ──
export const PREDEFINED_TAGS = [
  'login', 'admin', 'api', 'interesting', 'follow-up',
  'credential', 'sensitive', 'default-install', 'misconfigured',
  'out-of-scope', 'potential-customer',
] as const

export const TAG_COLORS: Record<string, string> = {
  login: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  admin: 'bg-red-500/15 text-red-400 border-red-500/30',
  api: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  interesting: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  'follow-up': 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  credential: 'bg-pink-500/15 text-pink-400 border-pink-500/30',
  sensitive: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  'default-install': 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  misconfigured: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  'out-of-scope': 'bg-gray-500/15 text-gray-400 border-gray-500/30',
  'potential-customer': 'bg-orange-600/15 text-orange-300 border-orange-600/30',
}

export const TAG_COLOR_DEFAULT = 'bg-gray-500/15 text-gray-400 border-gray-500/30'

// Per-tool configurable fields (label, key, input type, placeholder default)
export type ScanField = { label: string; key: string; type: string; placeholder?: string; options?: { value: string; label: string }[] }

export const SCAN_FIELDS: Record<string, ScanField[]> = {
  masscan: [
    { label: 'Target IP / CIDR', key: 'target', type: 'text', placeholder: '192.168.1.0/24' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '0-65535' },
    { label: 'Rate (pps)', key: 'rate', type: 'number', placeholder: '1000' },
    { label: 'Timeout (seconds, 0 = no limit)', key: 'timeout_seconds', type: 'number', placeholder: '0' },
  ],
  nmap: [
    { label: 'Target IP / CIDR', key: 'target', type: 'text', placeholder: '192.168.1.100' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '--top-ports 100' },
    { label: 'Service Detection (-sV)', key: 'service_detection', type: 'select', options: [{ value: '', label: 'Default (env)' }, { value: 'true', label: 'Enabled' }, { value: 'false', label: 'Disabled' }] },
    { label: 'Version Intensity (0-9)', key: 'version_intensity', type: 'select', options: [{ value: '', label: 'Default (env)' }, ...Array.from({ length: 10 }, (_, i) => ({ value: String(i), label: `${i}${i === 0 ? ' (light)' : i === 9 ? ' (all probes)' : ''}` }))] },
    { label: 'OS Detection (-O)', key: 'os_detection', type: 'select', options: [{ value: '', label: 'No' }, { value: 'true', label: 'Yes' }] },
    { label: 'NSE Scripts', key: 'scripts', type: 'select', options: [{ value: '', label: 'Default (env)' }, { value: 'default', label: 'default' }, { value: 'vuln', label: 'vuln (CVE checks)' }, { value: 'auth', label: 'auth (auth bypass)' }, { value: 'safe', label: 'safe (non-intrusive)' }, { value: 'discovery', label: 'discovery' }, { value: 'vuln,auth', label: 'vuln + auth' }, { value: 'default,vuln', label: 'default + vuln' }, { value: 'banner,http-title,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos', label: 'banner suite' }, { value: 'http-enum,http-headers,http-methods,http-robots.txt', label: 'http enum' }, { value: 'smb-enum-shares,smb-enum-users,smb-os-discovery', label: 'SMB enum' }, { value: 'dns-brute,dns-zone-transfer', label: 'DNS enum' }, { value: 'vuln,safe,http-enum,smb-enum-shares,smb-enum-users,smb-os-discovery,dns-brute', label: 'vuln + safe + enum' }] },
    { label: 'Script Args (optional)', key: 'script_args', type: 'text', placeholder: 'vulns.showall,http-enum.basepath=/api' },
    { label: 'Timing (T0-T5)', key: 'timing', type: 'select', options: [{ value: '', label: 'T4 (default)' }, { value: 'T0', label: 'T0 (paranoid)' }, { value: 'T1', label: 'T1 (sneaky)' }, { value: 'T2', label: 'T2 (polite)' }, { value: 'T3', label: 'T3 (normal)' }, { value: 'T4', label: 'T4 (aggressive)' }, { value: 'T5', label: 'T5 (insane)' }] },
    { label: 'Extra Args (advanced)', key: 'extra_args', type: 'text', placeholder: '--min-rate 100 --max-retries 2' },
    { label: 'Timeout (seconds, 0 = use default)', key: 'timeout_seconds', type: 'number', placeholder: '1800' },
  ],
  'nmap-tcp': [
    { label: 'Target IP / CIDR', key: 'target', type: 'text', placeholder: '192.168.1.100' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '--top-ports 100' },
    { label: 'Service Detection (-sV)', key: 'service_detection', type: 'select', options: [{ value: '', label: 'Default (env)' }, { value: 'true', label: 'Enabled' }, { value: 'false', label: 'Disabled' }] },
    { label: 'Version Intensity (0-9)', key: 'version_intensity', type: 'select', options: [{ value: '', label: 'Default (env)' }, ...Array.from({ length: 10 }, (_, i) => ({ value: String(i), label: `${i}${i === 0 ? ' (light)' : i === 9 ? ' (all probes)' : ''}` }))] },
    { label: 'OS Detection (-O)', key: 'os_detection', type: 'select', options: [{ value: '', label: 'No' }, { value: 'true', label: 'Yes' }] },
    { label: 'NSE Scripts', key: 'scripts', type: 'select', options: [{ value: '', label: 'Default (env)' }, { value: 'default', label: 'default' }, { value: 'vuln', label: 'vuln (CVE checks)' }, { value: 'auth', label: 'auth (auth bypass)' }, { value: 'safe', label: 'safe (non-intrusive)' }, { value: 'vuln,auth', label: 'vuln + auth' }, { value: 'default,vuln', label: 'default + vuln' }, { value: 'banner,http-title,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos', label: 'banner suite' }, { value: 'http-enum,http-headers,http-methods,http-robots.txt', label: 'http enum' }, { value: 'smb-enum-shares,smb-enum-users,smb-os-discovery', label: 'SMB enum' }] },
    { label: 'Script Args (optional)', key: 'script_args', type: 'text', placeholder: 'vulns.showall' },
    { label: 'Timing (T0-T5)', key: 'timing', type: 'select', options: [{ value: '', label: 'T4 (default)' }, { value: 'T0', label: 'T0 (paranoid)' }, { value: 'T1', label: 'T1 (sneaky)' }, { value: 'T2', label: 'T2 (polite)' }, { value: 'T3', label: 'T3 (normal)' }, { value: 'T4', label: 'T4 (aggressive)' }, { value: 'T5', label: 'T5 (insane)' }] },
    { label: 'Extra Args (advanced)', key: 'extra_args', type: 'text', placeholder: '--min-rate 100' },
    { label: 'Timeout (seconds, 0 = use default)', key: 'timeout_seconds', type: 'number', placeholder: '1800' },
  ],
  full: [
    { label: 'Target IP / CIDR', key: 'target', type: 'text', placeholder: '192.168.1.0/24' },
    { label: 'Rate (pps)', key: 'rate', type: 'number', placeholder: '1000' },
    { label: 'Timeout per nmap batch (seconds, 0 = default)', key: 'timeout_seconds', type: 'number', placeholder: '1800' },
  ],
  udp: [
    { label: 'Target IP', key: 'target', type: 'text', placeholder: '192.168.1.100' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '53,161,445' },
    { label: 'Timeout (seconds, 0 = use default)', key: 'timeout_seconds', type: 'number', placeholder: '1800' },
  ],
  'burp-scan': [
    { label: 'Target URLs (one per line)', key: 'target_urls', type: 'textarea', placeholder: 'https://target.com\nhttps://target.com/app' },
    { label: 'Scan Mode', key: 'scan_config', type: 'select', options: [{ value: 'default', label: 'Crawl & Audit (lightweight)' }, { value: 'fast', label: 'Crawl (fastest)' }, { value: 'deep', label: 'Audit (all checks)' }] },
    { label: 'SOCKS Proxy (auto-configure Burp)', key: 'burp_proxy', type: 'text', placeholder: 'socks5://node-manager:10123' },
  ],
  nuclei: [
    { label: 'Target URL (optional)', key: 'target', type: 'text', placeholder: 'http://192.168.1.100' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '80,443,8080' },
    { label: 'Severity', key: 'severity', type: 'text', placeholder: 'medium,high,critical' },
    { label: 'Tags (comma-sep or preset)', key: 'tags', type: 'text', placeholder: 'exposure,misconfig,tech,panel' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  web: [
    { label: 'Target URLs (one per line)', key: 'target_urls', type: 'textarea', placeholder: 'http://192.168.1.100\nhttp://192.168.1.101:8080' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '80,443,8080' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  pipeline: [
    { label: 'Target URL', key: 'target_url', type: 'text', placeholder: 'https://demo.testfire.net' },
    { label: 'Wordlist', key: 'wordlist', type: 'text', placeholder: 'medium' },
    { label: 'Max Paths', key: 'max_paths', type: 'number', placeholder: '50' },
    { label: 'Skip wafw00f', key: 'skip_wafw00f', type: 'toggle', placeholder: 'false' },
    { label: 'Skip Katana', key: 'skip_katana', type: 'toggle', placeholder: 'false' },
    { label: 'Skip Playwright', key: 'skip_playwright', type: 'toggle', placeholder: 'false' },
    { label: 'Skip Gobuster', key: 'skip_gobuster', type: 'toggle', placeholder: 'false' },
    { label: 'Skip Nikto', key: 'skip_nikto', type: 'toggle', placeholder: 'false' },
    { label: 'Skip Nuclei', key: 'skip_nuclei', type: 'toggle', placeholder: 'false' },
    { label: 'Skip ZAP', key: 'skip_zap', type: 'toggle', placeholder: 'false' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  httpx: [
    { label: 'Target IPs (comma-sep)', key: 'targets', type: 'text', placeholder: '192.168.1.100,192.168.1.101' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '80,443,8080' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  katana: [
    { label: 'Target URLs (comma-sep)', key: 'targets', type: 'text', placeholder: 'http://192.168.1.100' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '80,443,8080' },
    { label: 'Depth', key: 'depth', type: 'number', placeholder: '3' },
    { label: 'XHR Extraction (API calls)', key: 'xhr_extraction', type: 'toggle', placeholder: 'true' },
    { label: 'Form Extraction', key: 'form_extraction', type: 'toggle', placeholder: 'true' },
    { label: 'Known Files (robots.txt, sitemap)', key: 'known_files', type: 'text', placeholder: 'all' },
    { label: 'Headless Browser', key: 'headless', type: 'toggle', placeholder: 'false' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  naabu: [
    { label: 'Target IPs / CIDRs (comma-sep)', key: 'targets', type: 'text', placeholder: '192.168.1.0/24' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '1-1000' },
  ],
  subfinder: [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com,sub.example.com' },
  ],
  dnsx: [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com,sub.example.com' },
  ],
  'subdomain-takeover': [
    { label: 'Subdomains (comma-sep)', key: 'targets', type: 'text', placeholder: 'api.example.com,cdn.example.com' },
    { label: 'Timeout (seconds)', key: 'timeout', type: 'text', placeholder: '30' },
  ],
  tlsx: [
    { label: 'Targets (comma-sep, or "from_httpx" / "from_db")', key: 'targets', type: 'text', placeholder: 'from_httpx' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '443,8443' },
  ],
  playwright: [
    { label: 'Target URL', key: 'target_url', type: 'text', placeholder: 'https://demo.testfire.net' },
    { label: 'Capture DOM + Content Intel', key: 'capture_dom', type: 'toggle', placeholder: 'true' },
    { label: 'Capture Screenshots', key: 'capture_screenshots', type: 'toggle', placeholder: 'true' },
    { label: 'Run Security Checks', key: 'run_security_checks', type: 'toggle', placeholder: 'true' },
    { label: 'Use ZAP Proxy', key: 'use_zap_proxy', type: 'toggle', placeholder: 'true' },
    { label: 'ZAP Spider', key: 'zap_spider', type: 'toggle', placeholder: 'false' },
    { label: 'ZAP Active Scan', key: 'zap_active_scan', type: 'toggle', placeholder: 'false' },
    { label: 'Timeout (seconds)', key: 'timeout', type: 'text', placeholder: '30' },
  ],
  gobuster: [
    { label: 'Target URL', key: 'target_url', type: 'text', placeholder: 'https://demo.testfire.net' },
    { label: 'Wordlist', key: 'wordlist', type: 'text', placeholder: 'medium (small/medium/big/common/raft-small/raft-medium/api/quickhits)' },
    { label: 'Timeout (seconds)', key: 'timeout_sec', type: 'text', placeholder: '600' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  'content-recon': [
    { label: 'Target URLs (one per line, or single URL)', key: 'target_urls', type: 'textarea', placeholder: 'https://blog.example.com\nhttps://app.example.com' },
    { label: 'Spider Site (Katana crawl)', key: 'include_spider', type: 'toggle', placeholder: 'false' },
    { label: 'Spider Depth', key: 'spider_depth', type: 'text', placeholder: '3 (1-5)' },
    { label: 'Run Gobuster (directory brute-force)', key: 'run_gobuster', type: 'toggle', placeholder: 'false' },
    { label: 'Wordlist (if Gobuster enabled)', key: 'wordlist', type: 'text', placeholder: 'medium (small/medium/big/common/raft-small/api)' },
    { label: 'Max Playwright URLs', key: 'max_playwright_urls', type: 'text', placeholder: '50' },
    { label: 'Extract PDFs (download & extract text/metadata)', key: 'extract_pdfs', type: 'toggle', placeholder: 'false' },
    { label: 'Extract EXIF (image metadata for scope intel)', key: 'extract_exif', type: 'toggle', placeholder: 'false' },
    { label: 'Generate Wordlist (CeWL-style from crawled content)', key: 'generate_wordlist', type: 'toggle', placeholder: 'false' },
    { label: 'Capture Screenshot (main page only)', key: 'include_screenshots', type: 'toggle', placeholder: 'true' },
    { label: 'Screenshot All Discovered URLs', key: 'screenshot_all', type: 'toggle', placeholder: 'false' },
    { label: 'ZAP Passive Checkpoint (observe traffic, no active scan)', key: 'zap_checkpoint', type: 'toggle', placeholder: 'true' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  subzy: [
    { label: 'Subdomains (comma-sep or from scope)', key: 'targets', type: 'text', placeholder: 'sub1.example.com,sub2.example.com' },
  ],
  golinkfinder: [
    { label: 'Target URL', key: 'target_url', type: 'text', placeholder: 'https://example.com' },
  ],
  'email-enum': [
    { label: 'Domain', key: 'target', type: 'text', placeholder: 'example.com' },
    { label: 'DKIM Selectors (comma-sep, optional)', key: 'dkim_selectors', type: 'text', placeholder: 'google,selector1,selector2,default' },
  ],
  'dns-enum': [
    { label: 'Domain', key: 'target', type: 'text', placeholder: 'example.com' },
    { label: 'Reverse DNS CIDR (optional)', key: 'reverse_cidr', type: 'text', placeholder: '192.168.1.0/24' },
  ],
  'service-enum': [
    { label: 'Domain', key: 'target', type: 'text', placeholder: 'example.com' },
    { label: 'Services (comma-sep)', key: 'services', type: 'text', placeholder: 'email,dns (or: all)' },
    { label: 'Reverse DNS CIDR (optional)', key: 'reverse_cidr', type: 'text', placeholder: '192.168.1.0/24' },
    { label: 'DKIM Selectors (comma-sep, optional)', key: 'dkim_selectors', type: 'text', placeholder: 'google,selector1,selector2,default' },
  ],
  nikto: [
    { label: 'Target URL', key: 'target_url', type: 'text', placeholder: 'http://192.168.1.100' },
    { label: 'Ports', key: 'ports', type: 'text', placeholder: '80,443,8080' },
    { label: 'Tuning', key: 'tuning', type: 'text', placeholder: 'e.g. 1234 (optional)' },
  ],
  uncover: [
    { label: 'Search Query', key: 'query', type: 'text', placeholder: 'org:"Example Corp"' },
    { label: 'Engine', key: 'engine', type: 'text', placeholder: 'shodan' },
    { label: 'Limit', key: 'limit', type: 'number', placeholder: '100' },
  ],
  chaos: [
    { label: 'Domain', key: 'target', type: 'text', placeholder: 'example.com' },
  ],
  shuffledns: [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com' },
  ],
  vulnx: [
    { label: 'Product', key: 'product', type: 'text', placeholder: 'Apache HTTP Server' },
    { label: 'Version', key: 'version', type: 'text', placeholder: '2.4.51' },
    { label: 'Banner / Keyword', key: 'keyword', type: 'text', placeholder: 'OpenSSH 8.9' },
    { label: 'Severity', key: 'severity', type: 'text', placeholder: 'critical,high' },
    { label: 'Limit', key: 'limit', type: 'number', placeholder: '100' },
  ],
  'vulnx-scope': [
    { label: 'Engagement ID (optional)', key: 'engagement_id', type: 'text', placeholder: 'Leave blank for all assets' },
    { label: 'Severity Filter', key: 'severity', type: 'text', placeholder: 'critical,high,medium' },
    { label: 'Max CVEs per software', key: 'limit', type: 'number', placeholder: '100' },
  ],
  'recon-pipeline': [
    { label: 'Targets (comma-sep: domains, IPs, ASNs)', key: 'targets', type: 'text', placeholder: 'example.com,192.168.1.0/24,AS13335' },
    { label: 'Skip Phases (comma-sep, optional)', key: 'skip_phases_str', type: 'text', placeholder: 'alterx,shuffledns,crtsh,censys,asnmap,httpx,tlsx,whatweb' },
    { label: 'Uncover Engine', key: 'engine', type: 'text', placeholder: 'shodan' },
    { label: 'Uncover Limit', key: 'limit', type: 'number', placeholder: '100' },
  ],
  crtsh: [
    { label: 'Domain', key: 'target', type: 'text', placeholder: 'example.com' },
  ],
  'cloud-tenant': [
    { label: 'Domain', key: 'target', type: 'text', placeholder: 'contoso.com' },
  ],
  whatweb: [
    { label: 'Target URLs (comma-sep)', key: 'targets', type: 'text', placeholder: 'http://192.168.1.100,https://example.com' },
    { label: 'Aggression (1=stealthy, 3=aggressive, 4=heavy)', key: 'aggression', type: 'number', placeholder: '1' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  brutus: [
    { label: 'Target IPs (comma-sep)', key: 'targets', type: 'text', placeholder: '192.168.1.100,10.0.0.1' },
    { label: 'Protocols (comma-sep)', key: 'protocols', type: 'text', placeholder: 'ssh,ftp,smb' },
    { label: 'Usernames (comma-sep)', key: 'usernames', type: 'text', placeholder: 'admin,root,user' },
    { label: 'Passwords (comma-sep, or select wordlist below)', key: 'passwords', type: 'text', placeholder: 'admin,password,123456' },
    { label: 'Secret Type', key: 'secret_type', type: 'text', placeholder: 'password' },
  ],
  amass: [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com,sub.example.com' },
  ],
  gau: [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com' },
  ],
  waybackurls: [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com' },
  ],
  trufflehog: [
    { label: 'Target (repo URL, org, or path)', key: 'target', type: 'text', placeholder: 'https://github.com/org/repo' },
    { label: 'Scan Type', key: 'scan_type', type: 'text', placeholder: 'git' },
  ],
  censys: [
    { label: 'Query', key: 'query', type: 'text', placeholder: 'services.port: 443 AND location.country: US' },
    { label: 'Search Type (hosts/certs/subdomains)', key: 'search_type', type: 'text', placeholder: 'hosts' },
    { label: 'Results Per Page', key: 'per_page', type: 'number', placeholder: '100' },
    { label: 'Pages', key: 'pages', type: 'number', placeholder: '1' },
  ],
  gowitness: [
    { label: 'Target URLs (one per line)', key: 'targets', type: 'textarea', placeholder: 'https://example.com\nhttps://example.com:8443' },
    { label: 'Timeout (sec)', key: 'timeout', type: 'number', placeholder: '10' },
    { label: 'Resolution', key: 'resolution', type: 'text', placeholder: '1440x900' },
  ],
  whois: [
    { label: 'Targets (domains/IPs, comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com,10.0.0.1,target.org' },
  ],
  wafw00f: [
    { label: 'Target URLs (comma-sep)', key: 'targets', type: 'text', placeholder: 'https://example.com,https://target.com' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  greyhatwarfare: [
    { label: 'Search Query', key: 'query', type: 'text', placeholder: 'company.com or keyword' },
    { label: 'Search Type (buckets/files)', key: 'search_type', type: 'text', placeholder: 'buckets' },
    { label: 'Limit', key: 'limit', type: 'number', placeholder: '100' },
  ],
  ffuf: [
    { label: 'Target URL (must contain FUZZ)', key: 'target_url', type: 'text', placeholder: 'http://target/FUZZ' },
    { label: 'Extensions (comma-sep)', key: 'extensions', type: 'text', placeholder: '.php,.html,.txt' },
    { label: 'Filter Status Codes', key: 'filter_code', type: 'text', placeholder: '404,403' },
    { label: 'Match Status Codes', key: 'match_code', type: 'text', placeholder: '200,301' },
    { label: 'Rate (req/sec)', key: 'rate', type: 'number', placeholder: '100' },
      { label: 'Route through Burp', key: 'burp_proxy', type: 'toggle', placeholder: 'false' },
  ],
  netexec: [
    { label: 'Target IPs (comma-sep)', key: 'targets', type: 'text', placeholder: '192.168.1.100,10.0.0.0/24' },
    { label: 'Protocol', key: 'protocol', type: 'text', placeholder: 'smb' },
    { label: 'Username', key: 'username', type: 'text', placeholder: 'admin' },
    { label: 'Password', key: 'password', type: 'text', placeholder: '' },
    { label: 'NTLM Hash (pass-the-hash)', key: 'hash', type: 'text', placeholder: 'aad3b435b51404eeaad3b435b51404ee:...' },
    { label: 'Domain', key: 'domain', type: 'text', placeholder: 'CORP' },
    { label: 'Module (optional)', key: 'module', type: 'text', placeholder: 'spider_plus, enum_shares' },
  ],
  impacket: [
    { label: 'Target IP', key: 'target', type: 'text', placeholder: '192.168.1.100' },
    { label: 'Tool', key: 'impacket_tool', type: 'text', placeholder: 'secretsdump' },
    { label: 'Username', key: 'username', type: 'text', placeholder: 'admin' },
    { label: 'Password', key: 'password', type: 'text', placeholder: '' },
    { label: 'NTLM Hash', key: 'hash', type: 'text', placeholder: '' },
    { label: 'Domain', key: 'domain', type: 'text', placeholder: 'CORP' },
  ],
  hashcat: [
    { label: 'Hashes (one per line)', key: 'hashes', type: 'textarea', placeholder: '5f4dcc3b5aa765d61d8327deb882cf99\naad3b435b51404ee...' },
    { label: 'Hash Type (mode number)', key: 'hash_type', type: 'text', placeholder: '0 (md5), 1000 (ntlm), 13100 (kerberoast)' },
    { label: 'Wordlist Path', key: 'wordlist', type: 'text', placeholder: '/app/wordlists/rockyou.txt' },
  ],
  'passive-recon': [
    { label: 'Domains (comma-sep)', key: 'targets', type: 'text', placeholder: 'example.com,sub.example.com' },
  ],
  'prowler-import': [],
  'scoutsuite-import': [],
  'pacu-import': [],
  'cloudfox-import': [],
  'azurehound-import': [],
  'microburst-import': [],
}

// Keys that are target-related (not tool options) — skip these in Tool Options tab
export const TARGET_FIELD_KEYS = new Set([
  'target', 'targets', 'target_url', 'target_urls', 'query', 'hashes',
  'product', 'version', 'keyword', // vulnx search params
  'username', 'password', 'hash', 'domain', // credential params
  'usernames', 'passwords', // brutus credential params
])

// CLI flags/options each tool uses — shown in Tool Options for reference
export type CliOption = {
  flag: string        // e.g. "-p", "--rate"
  desc: string        // short description
  paramKey?: string   // maps to SCAN_FIELDS key (if configurable via UI)
  defaultValue?: string // hardcoded default in runner
}

export const TOOL_CLI_OPTIONS: Record<string, CliOption[]> = {
  masscan: [
    { flag: '--rate', desc: 'Packets per second', paramKey: 'rate', defaultValue: '1000' },
    { flag: '-p', desc: 'Port range (all ports by default)', paramKey: 'ports', defaultValue: '0-65535' },
    { flag: '--wait', desc: 'Wait time after scan (sec)', defaultValue: '30' },
  ],
  nmap: [
    { flag: '-sS/-sT', desc: 'Scan type (SYN / TCP connect)', defaultValue: '-sS' },
    { flag: '-T', desc: 'Timing template (0=paranoid … 5=insane)', defaultValue: '4' },
    { flag: '--open', desc: 'Only show open ports (yes/no)', defaultValue: 'yes' },
    { flag: '-p', desc: 'Port range or --top-ports N', paramKey: 'ports', defaultValue: '--top-ports 100' },
    { flag: '-sV', desc: 'Service version detection (yes/no)', defaultValue: 'yes' },
    { flag: '--script', desc: 'NSE scripts (comma-sep)', defaultValue: 'default' },
  ],
  'nmap-tcp': [
    { flag: '-T', desc: 'Timing template (0=paranoid … 5=insane)', defaultValue: '4' },
    { flag: '--open', desc: 'Only show open ports (yes/no)', defaultValue: 'yes' },
    { flag: '-p', desc: 'Port range or --top-ports N', paramKey: 'ports', defaultValue: '--top-ports 100' },
    { flag: '-sV', desc: 'Service version detection (yes/no)', defaultValue: 'yes' },
  ],
  full: [
    { flag: '-p', desc: 'Port range', defaultValue: '1-65535' },
    { flag: '--rate', desc: 'Masscan packets per second', paramKey: 'rate', defaultValue: '1000' },
  ],
  udp: [
    { flag: '-p', desc: 'UDP ports', paramKey: 'ports', defaultValue: '53,67,68,69,111,123,135,137,161,445,500,514,1434,1900,5353' },
    { flag: '-sV', desc: 'Service version detection (yes/no)', defaultValue: 'yes' },
    { flag: '-Pn', desc: 'Skip host discovery (yes/no)', defaultValue: 'yes' },
    { flag: '--version-intensity', desc: 'Version probe intensity (0-9)', defaultValue: '0' },
  ],
  nuclei: [
    { flag: '-severity', desc: 'Filter by severity', paramKey: 'severity', defaultValue: 'low,medium,high,critical' },
    { flag: '-c', desc: 'Concurrency (parallel templates)', defaultValue: '50' },
    { flag: '-rl', desc: 'Rate limit (req/sec)', defaultValue: '150' },
    { flag: '-timeout', desc: 'Request timeout (sec)', defaultValue: '10' },
    { flag: '-retries', desc: 'Retry count', defaultValue: '1' },
    { flag: '-t', desc: 'Templates directory', defaultValue: '/opt/nuclei-templates' },
    { flag: '-tags', desc: 'Filter templates by tags (comma-sep)', defaultValue: '' },
  ],
  httpx: [
    { flag: '-ports', desc: 'Ports to probe', paramKey: 'ports', defaultValue: '80,443,8080' },
    { flag: '-follow-redirects', desc: 'Follow HTTP redirects (yes/no)', defaultValue: 'yes' },
    { flag: '-tech-detect', desc: 'Technology detection (yes/no)', defaultValue: 'yes' },
    { flag: '-timeout', desc: 'Request timeout (sec)', defaultValue: '5' },
    { flag: '-threads', desc: 'Number of threads', defaultValue: '50' },
    { flag: '-rate-limit', desc: 'Requests per second (0=unlimited)', defaultValue: '150' },
  ],
  katana: [
    { flag: '-depth', desc: 'Crawl depth', paramKey: 'depth', defaultValue: '3' },
    { flag: '-js-crawl', desc: 'Enable JavaScript crawling (yes/no)', defaultValue: 'yes' },
    { flag: '-concurrency', desc: 'Number of concurrent fetchers', defaultValue: '10' },
    { flag: '-rate-limit', desc: 'Requests per second (0=unlimited)', defaultValue: '150' },
  ],
  naabu: [
    { flag: '-p', desc: 'Port range', paramKey: 'ports', defaultValue: '1-1000' },
    { flag: '-rate', desc: 'Rate limit (packets/sec)', paramKey: 'rate', defaultValue: '1000' },
    { flag: '-top-ports', desc: 'Scan top N ports (overrides -p)', defaultValue: '' },
    { flag: '-retries', desc: 'Number of retries', defaultValue: '3' },
    { flag: '-timeout', desc: 'Timeout per probe (ms)', defaultValue: '5000' },
  ],
  tlsx: [
    { flag: '-p', desc: 'TLS ports', paramKey: 'ports', defaultValue: '443,8443' },
    { flag: '-timeout', desc: 'Connection timeout (sec)', defaultValue: '5' },
  ],
  subfinder: [
    { flag: '-sources', desc: 'Specific sources to use (comma-sep)', defaultValue: '' },
    { flag: '-timeout', desc: 'Timeout (minutes)', defaultValue: '30' },
    { flag: '-max-time', desc: 'Max enumeration time (minutes)', defaultValue: '10' },
  ],
  dnsx: [
    { flag: '-record-types', desc: 'DNS record types to query', defaultValue: 'A,AAAA,CNAME,MX,NS' },
    { flag: '-threads', desc: 'Number of concurrent resolvers', defaultValue: '100' },
    { flag: '-retry', desc: 'Number of retries per query', defaultValue: '2' },
  ],
  'subdomain-takeover': [
    { flag: '--timeout', desc: 'HTTP request timeout (seconds)', defaultValue: '30' },
    { flag: '--concurrent', desc: 'Number of concurrent checks', defaultValue: '10' },
    { flag: '--user-agent', desc: 'HTTP User-Agent string', defaultValue: 'Mozilla/5.0 (SubTakeOver Scanner)' },
  ],
  whatweb: [
    { flag: '-a', desc: 'Aggression level (1=stealthy … 4=heavy)', paramKey: 'aggression', defaultValue: '1' },
    { flag: '--max-threads', desc: 'Max concurrent threads', defaultValue: '25' },
  ],
  ffuf: [
    { flag: '-w', desc: 'Wordlist path', defaultValue: '/usr/share/seclists/Discovery/Web-Content/common.txt' },
    { flag: '-rate', desc: 'Requests per second', paramKey: 'rate', defaultValue: '100' },
    { flag: '-e', desc: 'File extensions', paramKey: 'extensions', defaultValue: '' },
    { flag: '-fc', desc: 'Filter HTTP status codes', paramKey: 'filter_code', defaultValue: '' },
    { flag: '-mc', desc: 'Match HTTP status codes', paramKey: 'match_code', defaultValue: '' },
    { flag: '-X', desc: 'HTTP method', defaultValue: 'GET' },
    { flag: '-t', desc: 'Number of threads', defaultValue: '40' },
    { flag: '-timeout', desc: 'Request timeout (sec)', defaultValue: '10' },
  ],
  nikto: [
    { flag: '-timeout', desc: 'Connection timeout (sec)', defaultValue: '10' },
    { flag: '-Tuning', desc: 'Test tuning categories (e.g. 1234)', paramKey: 'tuning', defaultValue: '' },
    { flag: '-maxtime', desc: 'Max scan time (sec)', defaultValue: '3600' },
    { flag: '-Pause', desc: 'Pause between requests (sec)', defaultValue: '0' },
  ],
  web: [
    { flag: '-t', desc: 'Gobuster threads', defaultValue: '50' },
    { flag: '-x', desc: 'Gobuster file extensions', defaultValue: 'php,html,txt' },
    { flag: '-s', desc: 'Gobuster match status codes', defaultValue: '200,301,302,403' },
    { flag: '-w', desc: 'Gobuster wordlist', defaultValue: 'medium' },
  ],
  pipeline: [
    { flag: 'max_paths', desc: 'Max paths from Gobuster to feed pipeline', paramKey: 'max_paths', defaultValue: '50' },
  ],
  gowitness: [
    { flag: '-T', desc: 'Page load timeout (sec)', paramKey: 'timeout', defaultValue: '10' },
    { flag: '--chrome-window-x/y', desc: 'Screenshot resolution', paramKey: 'resolution', defaultValue: '1440x900' },
    { flag: '--screenshot-format', desc: 'Image format (png/jpeg)', defaultValue: 'png' },
  ],
  amass: [
    { flag: '-passive', desc: 'Passive-only mode (yes/no)', defaultValue: 'yes' },
    { flag: '-timeout', desc: 'Timeout (minutes)', defaultValue: '30' },
  ],
  gau: [
    { flag: '--subs', desc: 'Include subdomains (yes/no)', defaultValue: 'yes' },
    { flag: '--threads', desc: 'Number of threads', defaultValue: '2' },
    { flag: '--providers', desc: 'Providers (wayback,commoncrawl,otx,urlscan)', defaultValue: 'wayback,commoncrawl,otx,urlscan' },
  ],
  waybackurls: [
    { flag: '--no-subs', desc: 'Exclude subdomains (yes/no)', defaultValue: 'no' },
  ],
  trufflehog: [
    { flag: '<scan_type>', desc: 'Scan type (git/github/filesystem/s3)', paramKey: 'scan_type', defaultValue: 'git' },
    { flag: '--concurrency', desc: 'Scanner concurrency', defaultValue: '8' },
  ],
  uncover: [
    { flag: '-e', desc: 'Search engine', paramKey: 'engine', defaultValue: 'shodan' },
    { flag: '-limit', desc: 'Result limit', paramKey: 'limit', defaultValue: '100' },
  ],
  whois: [
    { flag: 'targets', desc: 'Domains and/or IPs (comma-separated)', paramKey: 'targets', defaultValue: '' },
  ],
  wafw00f: [
    { flag: '-a', desc: 'Test all WAF signatures (yes/no)', defaultValue: 'no' },
  ],
  greyhatwarfare: [
    { flag: 'search_type', desc: 'Search buckets or files', paramKey: 'search_type', defaultValue: 'buckets' },
    { flag: 'limit', desc: 'Result limit', paramKey: 'limit', defaultValue: '100' },
  ],
  netexec: [
    { flag: '<protocol>', desc: 'Protocol (smb/ldap/winrm/ssh/mssql)', paramKey: 'protocol', defaultValue: 'smb' },
    { flag: '-M', desc: 'Module to run', paramKey: 'module', defaultValue: '' },
    { flag: '--timeout', desc: 'Connection timeout (sec)', defaultValue: '30' },
    { flag: '--jitter', desc: 'Jitter between connections (sec)', defaultValue: '0' },
  ],
  impacket: [
    { flag: '<tool>', desc: 'Impacket tool name', paramKey: 'impacket_tool', defaultValue: 'secretsdump' },
    { flag: '--timeout', desc: 'Connection timeout (sec)', defaultValue: '30' },
  ],
  hashcat: [
    { flag: '-m', desc: 'Hash type mode number', paramKey: 'hash_type', defaultValue: '0' },
    { flag: '-w', desc: 'Workload profile (1=low … 4=nightmare)', defaultValue: '2' },
    { flag: '-r', desc: 'Rules file path', defaultValue: '' },
    { flag: '--force', desc: 'Ignore warnings (yes/no)', defaultValue: 'yes' },
  ],
  censys: [
    { flag: 'search_type', desc: 'Search type (hosts/certs/subdomains)', paramKey: 'search_type', defaultValue: 'hosts' },
    { flag: 'per_page', desc: 'Results per page', paramKey: 'per_page', defaultValue: '100' },
    { flag: 'pages', desc: 'Number of pages', paramKey: 'pages', defaultValue: '1' },
  ],
  vulnx: [
    { flag: '--limit', desc: 'Result limit', paramKey: 'limit', defaultValue: '100' },
    { flag: '--severity', desc: 'Filter by severity', paramKey: 'severity', defaultValue: '' },
  ],
  'vulnx-scope': [
    { flag: '--limit', desc: 'Max CVEs per software', paramKey: 'limit', defaultValue: '100' },
    { flag: '--severity', desc: 'Filter by severity', paramKey: 'severity', defaultValue: '' },
  ],
  brutus: [
    { flag: '<protocols>', desc: 'Target protocols', paramKey: 'protocols', defaultValue: 'ssh' },
    { flag: 'secret_type', desc: 'Credential type', paramKey: 'secret_type', defaultValue: 'password' },
    { flag: 'max_threads', desc: 'Max concurrent attempts', defaultValue: '10' },
    { flag: 'timeout', desc: 'Connection timeout (sec)', defaultValue: '10' },
  ],
  shuffledns: [
    { flag: '-t', desc: 'Number of threads', defaultValue: '100' },
    { flag: '-d', desc: 'Domains to bruteforce', defaultValue: '' },
  ],
  crtsh: [
    { flag: 'include_expired', desc: 'Include expired certs (yes/no)', defaultValue: 'yes' },
  ],
  'passive-recon': [
    { flag: 'include_cert_chain', desc: 'Cert serial chain discovery (yes/no)', defaultValue: 'yes' },
    { flag: 'cert_chain_max_iterations', desc: 'Max cert chain rounds (1-3)', defaultValue: '2' },
    { flag: 'include_spider', desc: 'Enable katana spider (yes/no)', defaultValue: 'no' },
    { flag: 'spider_depth', desc: 'Katana spider depth (1-5)', defaultValue: '2' },
  ],
  'recon-pipeline': [
    { flag: 'skip_phases', desc: 'Phases to skip (comma-sep)', defaultValue: '' },
    { flag: 'uncover_engine', desc: 'Uncover search engine', defaultValue: 'shodan' },
    { flag: 'uncover_limit', desc: 'Uncover result limit', defaultValue: '100' },
  ],
}
