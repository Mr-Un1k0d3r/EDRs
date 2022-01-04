#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>

VOID DumpListOfExport(VOID *lib, BOOL bNt);
VOID GetBytesByName(HANDLE hDll, CHAR *name, BOOL bNt);
BOOL IsFalsePositive(CHAR *name);
VOID ListLoadedDlls();

VOID ListLoadedDlls() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    printf("Listing loaded modules\n------------------------------------------\n");
    if(Module32First(hSnap, &me32)) {
        do {
            printf("%s is loaded at 0x%p.\n", me32.szExePath, me32.modBaseAddr);

        } while(Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);
}

VOID DumpListOfExport(VOID *lib, BOOL bNt) {
    DWORD dwIter = 0;
    CHAR* base = (CHAR*)lib;
    CHAR* PE = base + (unsigned char)*(base + 0x3c);
    DWORD ExportDirectoryOffset = *((DWORD*)PE + (0x8a / 4));
    CHAR* ExportDirectory = base + ExportDirectoryOffset;
    DWORD dwFunctionsCount = *((DWORD*)ExportDirectory + (0x14 / 4));
    DWORD OffsetNamesTableOffset = *((DWORD*)ExportDirectory + (0x20 / 4));
    CHAR* OffsetNamesTable = base + OffsetNamesTableOffset;

    printf("------------------------------------------\nBASE\t\t\t0x%p\t%s\nPE\t\t\t0x%p\t%s\nExportTableOffset\t0x%p\nOffsetNameTable\t\t0x%p\nFunctions Count\t\t0x%x (%d)\n------------------------------------------\n",
    base, base, PE, PE, ExportDirectory, OffsetNamesTable, dwFunctionsCount, dwFunctionsCount);

    for(dwIter; dwIter < dwFunctionsCount - 1; dwIter++) {
        DWORD64 offset = *((DWORD*)OffsetNamesTable + dwIter);
        CHAR* current = base + offset;
        GetBytesByName((HANDLE)lib, current, bNt);
    }
}

VOID GetBytesByName(HANDLE hDll, CHAR *name, BOOL bNt) {
    FARPROC ptr = GetProcAddress((HMODULE)hDll, name);
    DWORD* opcode = (DWORD*)*ptr;

	if(bNt) {
		if(name[0] != 'N' && name[1] != 't') {
			return;
		}
	}
	
    if((*opcode << 24) >> 24 == 0xe9) {
        if(!IsFalsePositive(name)) {
            printf("%s is hooked\n", name);
        }
    }
}

BOOL IsFalsePositive(CHAR *name) {
    DWORD dwSize = 41;
    DWORD i = 0;
    CHAR *FPs[] = { "_memicmp", "_strcmpi", "_stricmp", "_strnicmp", "RtlInitializeSListHead", "DbgQueryDebugFilterState","DbgSetDebugFilterState","EtwpGetCpuSpeed","LdrAccessResource","LdrCallEnclave","LdrProcessRelocationBlockEx","NtQuerySystemTime","RtlAddAtomToAtomTable","RtlBarrier","RtlCommitDebugInfo","RtlConstructCrossVmEventPath","RtlConstructCrossVmMutexPath","RtlConvertToAutoInheritSecurityObject","RtlCreateHashTableEx","RtlDeCommitDebugInfo","RtlDowncaseUnicodeChar","RtlEndWeakEnumerationHashTable","RtlEqualComputerName","RtlGetDeviceFamilyInfoEnum","RtlInitStringEx","RtlInitUTF8String","RtlInitUTF8StringEx","RtlInitWeakEnumerationHashTable","RtlInterlockedFlushSList","RtlInterlockedPushEntrySList","RtlInterlockedPushListSListEx","RtlSetTimer","RtlWeaklyEnumerateEntryHashTable","RtlWerpReportException","RtlWnfDllUnloadCallback","RtlpNtMakeTemporaryKey","ShipAssertMsgA","ShipAssertMsgW","TpSetTimer","ZwQuerySystemTime","towupper" };

    for(i; i < dwSize; i++) {
        if(strcmp(name, FPs[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

int main (int argc, char **argv) {
    CHAR *dll = argv[1];
    HANDLE hDll = LoadLibrary(dll);
	BOOL bNt = TRUE;
    printf("Loading %s\nHookFinder Mr.Un1k0d3r RingZer0 Team\n", dll);
    if(hDll == NULL) {
        ExitProcess(0);
    }
    // Force load the hooking DLL.
    FARPROC dummy = GetProcAddress(LoadLibrary("ntdll.dll"), "NtOpenProcess");
    
    ListLoadedDlls();
	
	if(argc > 2) {
		bNt = FALSE;
	} else {
		printf("***Listing Nt* API only\n\n");
	}
	
    DumpListOfExport(hDll, bNt);
    CloseHandle(hDll);
    printf("------------------------------------------\nCompleted\n");
    return 0;
}
