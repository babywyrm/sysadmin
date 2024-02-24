/*
 * A simple Windows 32-bit DLL injector
 *
 * Note that this does not attempt to be "stealthy". If you are
 * using this to inject hacks into games, prepare to be banned.
 * 
 * To start a process and inject a DLL before main() is called:
 *   CreateProcessWithDll("path/to/program.exe", "--program-args", "path/to/library.dll");
 *
 * To inject a DLL into an already-running process:
 *   InjectDllIntoProcess("program.exe", "path/to/library.dll");
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

void PrintLastError(const char *msg)
{
    DWORD err = GetLastError();
    char *buf = NULL;
    DWORD count = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buf,
        0,
        NULL);

    if (count != 0) {
        fprintf(stderr, "%s (0x%08x): %s", msg, err, buf);
        LocalFree(buf);
    } else {
        fprintf(stderr, "%s (0x%08x): Unknown error\n", msg, err);
    }
}

bool ReadNtHeader(HANDLE hProcess, void *baseAddress, IMAGE_NT_HEADERS32 *headers)
{
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, baseAddress, &dosHeader, sizeof(dosHeader), NULL)) {
        PrintLastError("Could not read DOS header");
        return false;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "DOS header signature mismatch (got 0x%04x)\n", dosHeader.e_magic);
        return false;
    }

    LONG ntHeaderOffset = dosHeader.e_lfanew;
    IMAGE_NT_HEADERS32 ntHeader;
    if (!ReadProcessMemory(hProcess, (char *)baseAddress + ntHeaderOffset, &ntHeader, sizeof(ntHeader), NULL)) {
        PrintLastError("Could not read NT header");
        return false;
    }
    if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "NT header signature mismatch (got 0x%08x)\n", ntHeader.Signature);
        return false;
    }
    if (ntHeader.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        fprintf(stderr, "NT optional header signature mismatch (got 0x%04x)\n", ntHeader.OptionalHeader.Magic);
        return false;
    }

    *headers = ntHeader;
    return true;
}

bool CreateSuspendedProcess(const char *exePath, const char *args, PROCESS_INFORMATION *processInfo)
{
    // Create the process in suspended mode
    // No need to create a copy of args since we're calling
    // the ANSI version which will internally copy the buffer
    STARTUPINFOA startupInfo = { 0 };
    startupInfo.cb = sizeof(startupInfo);
    bool success = CreateProcessA(
        exePath,
        (char *)args,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &startupInfo,
        processInfo);

    if (!success) {
        PrintLastError("Could not create suspended process");
    }
    return success;
}

bool PatchCode(HANDLE hProcess, void *address, size_t length, const void *newBytes, void *oldBytes)
{
    bool success = false;

    // Get write permissions to the code
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        PrintLastError("Could not modify code permissions");
        goto exit;
    }

    // Save the original bytes
    if (!ReadProcessMemory(hProcess, address, oldBytes, length, NULL)) {
        PrintLastError("Could not read original bytes");
        goto restore;
    }

    // Write the new bytes
    if (!WriteProcessMemory(hProcess, address, newBytes, length, NULL)) {
        PrintLastError("Could not write new bytes");
        goto restore;
    }

    // Flush instruction cache
    FlushInstructionCache(hProcess, address, length);

    success = true;

restore:
    // Restore original code permissions
    if (!VirtualProtectEx(hProcess, address, length, oldProtect, &oldProtect)) {
        PrintLastError("Could not restore original code permissions");
    }

exit:
    return success;
}

bool GetBaseAddress(HANDLE hProcess, HANDLE hMainThread, DWORD *base)
{
    PPEB peb;

    // Method 1: Rely on PEB pointer being stored in EBX upon startup
    // http://stackoverflow.com/questions/12808516/pointer-to-baseaddress-through-context-ebx8
    CONTEXT context;
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(hMainThread, &context)) {
        PrintLastError("Could not get main thread context");
        return false;
    }
    peb = (PPEB)context.Ebx;

    // Method 2: Use NtQueryInformationProcess to get PEB pointer
    // http://stackoverflow.com/questions/8336214/how-can-i-get-a-process-entry-point-address
    /*
#pragma comment(lib, "ntdll.lib")
    PROCESS_BASIC_INFORMATION info;
    if (!NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), NULL))) {
        fprintf(stderr, "Failed to get process info\n");
        return false;
    }
    peb = info.PebBaseAddress;
    */

    // Read base address from PEB
    if (!ReadProcessMemory(hProcess, &peb->Reserved3[1], base, sizeof(*base), NULL)) {
        PrintLastError("Could not read PEB -> base address");
        return false;
    }

    return true;
}

bool WaitForMainThreadInit(HANDLE hMainThread, DWORD entryPoint)
{
    while (true) {
        // Resume the thread
        if (ResumeThread(hMainThread) == (DWORD)-1) {
            PrintLastError("Could not resume main thread");
            return false;
        }

        // Give the thread some time to progress
        Sleep(100);

        // Suspend the thread to check its status
        if (SuspendThread(hMainThread) == (DWORD)-1) {
            PrintLastError("Could not suspend main thread");
            return false;
        }

        // Get control registers of the thread
        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(hMainThread, &context)) {
            PrintLastError("Could not get main thread context");
            return false;
        }

        // Are we at the entry point yet?
        if (context.Eip == entryPoint) {
            return true;
        }
    }
}

bool InjectDll(HANDLE hProcess, const char *dllPath)
{
    void *remoteDllPath = NULL;
    HANDLE loadLibraryThread = NULL;
    bool success = false;

    // Get the kernel32 module (which contains LoadLibrary)
    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    if (hKernel32 == NULL) {
        PrintLastError("Could not get kernel32 module");
        goto cleanup;
    }

    // Get LoadLibrary offset. Note that this is the address
    // in OUR process, but it's highly likely kernel32 is mapped
    // at the same address everywhere, so this is usually fine.
    LPTHREAD_START_ROUTINE loadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibrary == NULL) {
        PrintLastError("Could not find LoadLibraryA");
        goto cleanup;
    }

    // Get full DLL path (since target process may have a different current directory)
    char fullDllPath[MAX_PATH];
    DWORD fullDllPathLength = GetFullPathNameA(dllPath, sizeof(fullDllPath), fullDllPath, NULL);
    if (fullDllPathLength == 0) {
        PrintLastError("Could not get full DLL path");
        goto cleanup;
    }

    // Allocate space for the DLL path in the target process
    remoteDllPath = VirtualAllocEx(hProcess, NULL, fullDllPathLength + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteDllPath == NULL) {
        PrintLastError("Could not allocate space for DLL path");
        goto cleanup;
    }

    // Copy DLL path to target process
    if (!WriteProcessMemory(hProcess, remoteDllPath, fullDllPath, fullDllPathLength + 1, NULL)) {
        PrintLastError("Could not copy DLL path to process");
        goto cleanup;
    }

    // Create thread in the target process which calls LoadLibraryA(dllPath)
    loadLibraryThread = CreateRemoteThread(hProcess, NULL, 0, loadLibrary, remoteDllPath, 0, NULL);
    if (loadLibraryThread == NULL) {
        PrintLastError("Could not create LoadLibrary thread");
        goto cleanup;
    }

    // Wait for DllMain to execute
    WaitForSingleObject(loadLibraryThread, INFINITE);

    success = true;

cleanup:
    if (loadLibraryThread != NULL) {
        CloseHandle(loadLibraryThread);
    }
    if (remoteDllPath != NULL) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    }
    return success;
}

bool CreateProcessWithDlls(const char *exePath, const char *args, int numDlls, const char *dllPaths[])
{
    // https://opcode0x90.wordpress.com/2011/01/15/injecting-dll-into-process-on-load/
    HANDLE hProcess = NULL;
    HANDLE hMainThread = NULL;
    bool success = false;

    // Create the process in suspended mode
    PROCESS_INFORMATION processInfo;
    if (!CreateSuspendedProcess(exePath, args, &processInfo)) {
        fprintf(stderr, "Could not create process\n");
        goto cleanup;
    }

    hProcess = processInfo.hProcess;
    hMainThread = processInfo.hThread;

    // Get base address
    DWORD baseAddress;
    if (!GetBaseAddress(hProcess, hMainThread, &baseAddress)) {
        fprintf(stderr, "Could not get process base address\n");
        goto cleanup;
    }

    // Read NT headers to find entry point
    IMAGE_NT_HEADERS32 ntHeaders;
    if (!ReadNtHeader(hProcess, (void *)baseAddress, &ntHeaders)) {
        fprintf(stderr, "Could not read NT headers\n");
        goto cleanup;
    }

    // Entry point can be calculated from base + relative
    DWORD entryPoint = baseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint;

    // Patch entry point
    // 0xEB = JMP rel8
    // 0xFE = -2
    WORD origEntry;
    WORD newEntry = 0xFEEB;
    if (!PatchCode(hProcess, (void *)entryPoint, sizeof(WORD), &newEntry, &origEntry)) {
        fprintf(stderr, "Could not patch entry point\n");
        goto cleanup;
    }

    // Wait for main thread to reach entry point
    // The main thread will be suspended upon return
    if (!WaitForMainThreadInit(hMainThread, entryPoint)) {
        fprintf(stderr, "Waiting for main thread init failed\n");
        goto cleanup;
    }

    for (int i = 0; i < numDlls; ++i) {
        // Inject DLL into the process and wait for DllMain to execute
        if (!InjectDll(hProcess, dllPaths[i])) {
            fprintf(stderr, "Could not inject DLL: %s\n", dllPaths[i]);
            goto cleanup;
        }
    }

    // Restore entry point
    if (!PatchCode(hProcess, (void *)entryPoint, sizeof(WORD), &origEntry, &newEntry)) {
        fprintf(stderr, "Could not restore entry point\n");
        goto cleanup;
    }

    // Resume execution of main thread
    if (ResumeThread(hMainThread) == (DWORD)-1) {
        PrintLastError("Could not resume main thread");
        goto cleanup;
    }

    success = true;

cleanup:
    if (hMainThread != NULL) {
        CloseHandle(hMainThread);
    }
    if (hProcess != NULL) {
        if (!success) {
            TerminateProcess(hProcess, 1);
        }
        CloseHandle(hProcess);
    }
    return success;
}

bool CreateProcessWithDll(const char *exePath, const char *args, const char *dllPath)
{
    const char *dllPaths[1] = { dllPath };
    return CreateProcessWithDlls(exePath, args, 1, dllPaths);
}

DWORD FindProcessIdByName(const char *processName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintLastError("Could not create process snapshot");
        return 0;
    }

    DWORD pid = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    BOOL success = Process32First(snapshot, &entry);
    while (success) {
        if (strcmp(processName, entry.szExeFile) == 0) {
            pid = entry.th32ProcessID;
            break;
        }
        success = Process32Next(snapshot, &entry);
    }

    CloseHandle(snapshot);
    return pid;
}

HANDLE OpenProcessByName(const char *processName)
{
    DWORD pid = FindProcessIdByName(processName);
    if (pid == 0) {
        fprintf(stderr, "Could not find process\n");
        return NULL;
    }

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        pid);

    if (hProcess == NULL) {
        PrintLastError("Could not open process");
    }
    return hProcess;
}

bool InjectDllIntoProcess(const char *processName, const char *dllPath)
{
    HANDLE hProcess = NULL;
    bool success = false;

    // Open the running process
    hProcess = OpenProcessByName(processName);
    if (hProcess == NULL) {
        fprintf(stderr, "Could not open process\n");
        goto cleanup;
    }

    // Inject DLL into the process and wait for DllMain to execute
    if (!InjectDll(hProcess, dllPath)) {
        fprintf(stderr, "Could not inject DLL: %s\n", dllPath);
        goto cleanup;
    }

    success = true;

cleanup:
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }
    return success;
}
