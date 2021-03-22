#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

VOID DumpListOfExport(VOID *lib);
BOOL GetBytesByName(HANDLE hDll, CHAR *name);
BOOL IsFalsePositive(CHAR *name);

VOID DumpListOfExport(VOID *lib) {
    DWORD dwIter = 0;
    CHAR* base = lib;
    CHAR* PE = base + (unsigned char)*(base + 0x3c);
    DWORD ExportDirectoryOffset = *((DWORD*)PE + (0x8a / 4));
    CHAR* ExportDirectory = base + ExportDirectoryOffset;
    DWORD dwFunctionsCount = *((DWORD*)ExportDirectory + (0x14 / 4));
    DWORD OffsetNamesTableOffset = *((DWORD*)ExportDirectory + (0x20 / 4));
    DWORD* OffsetNamesTable = base + OffsetNamesTableOffset;

    printf("------------------------------------------\nBASE\t\t\t0x%p\t%s\nPE\t\t\t0x%p\t%s\nExportTableOffset\t0x%p\nOffsetNameTable\t\t0x%p\nFunctions Count\t\t0x%x (%d)\n------------------------------------------\n",
    base, base, PE, PE, ExportDirectory, OffsetNamesTable, dwFunctionsCount, dwFunctionsCount);

    for(dwIter; dwIter < dwFunctionsCount - 1; dwIter++) {
        DWORD64 offset = *(OffsetNamesTable + dwIter);
        CHAR* current = base + offset;
        GetBytesByName((HANDLE)lib, current);
    }
}

BOOL GetBytesByName(HANDLE hDll, CHAR *name) {
    FARPROC ptr = GetProcAddress(hDll, name);
    DWORD* opcode = (DWORD*)*ptr;

    if((*opcode << 24) >> 24 == 0xe9) {
        if(!IsFalsePositive(name)) {
            printf("%s is hooked\n", name);
        }
    }
}

BOOL IsFalsePositive(CHAR *name) {
    DWORD dwSize = 36;
    DWORD i = 0;
    CHAR *FPs[] = { "DbgQueryDebugFilterState","DbgSetDebugFilterState","EtwpGetCpuSpeed","LdrAccessResource","LdrCallEnclave","LdrProcessRelocationBlockEx","NtQuerySystemTime","RtlAddAtomToAtomTable","RtlBarrier","RtlCommitDebugInfo","RtlConstructCrossVmEventPath","RtlConstructCrossVmMutexPath","RtlConvertToAutoInheritSecurityObject","RtlCreateHashTableEx","RtlDeCommitDebugInfo","RtlDowncaseUnicodeChar","RtlEndWeakEnumerationHashTable","RtlEqualComputerName","RtlGetDeviceFamilyInfoEnum","RtlInitStringEx","RtlInitUTF8String","RtlInitUTF8StringEx","RtlInitWeakEnumerationHashTable","RtlInterlockedFlushSList","RtlInterlockedPushEntrySList","RtlInterlockedPushListSListEx","RtlSetTimer","RtlWeaklyEnumerateEntryHashTable","RtlWerpReportException","RtlWnfDllUnloadCallback","RtlpNtMakeTemporaryKey","ShipAssertMsgA","ShipAssertMsgW","TpSetTimer","ZwQuerySystemTime","towupper" };

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
    printf("Loading %s\nHookFinder Mr.Un1k0d3r RingZer0 Team\n", dll);
    if(hDll == NULL) {
        ExitProcess(0);
    }

    DumpListOfExport(hDll);
    CloseHandle(hDll);
    printf("------------------------------------------\nCompleted\n");
    return 0;
}
