#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <winnt.h>

VOID DumpListOfExport(VOID *lib, BOOL bNt);
VOID CheckJmp(CHAR *name, DWORD* address, BOOL bNt);
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

    IMAGE_DOS_HEADER* MZ = (IMAGE_DOS_HEADER*)lib;
    IMAGE_NT_HEADERS* PE = (IMAGE_NT_HEADERS*)((BYTE*)lib + MZ->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)lib + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *name = (DWORD*)((BYTE*)lib + export->AddressOfNames);

    DWORD i = 0;
    for(i; i < export->NumberOfNames; i++) 

{


        CheckJmp((CHAR*)lib + name[i], (DWORD*)GetProcAddress(lib, lib + name[i]), bNt);
    }    
}

VOID CheckJmp(CHAR *name, DWORD* address, BOOL bNt) {
    BYTE* opcode = (BYTE*)address;

    // Some EDRs hook more than Nt* API. Ex: LdrLoadDll 
    if(bNt) {
        if(!(name[0] == 'N' && name[1] == 't')) {
            return;
        }
    }

    // not all EDRs hook the first byte you will miss some hook
    if(*opcode == 0xe9) {
        printf("%s is hooked\n", name);
    }
}

int main (int argc, char **argv) {
    CHAR *dll = argv[1];
    HANDLE hDll = LoadLibrary(dll);
    BOOL bNt = TRUE;
	
    printf("Loading %s\nHookFinder Mr.Un1k0d3r RingZer0 Team\n", dll);
    if(hDll == NULL) {
        ExitProcess(0);
    }

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
