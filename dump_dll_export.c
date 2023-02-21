#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <winnt.h>

VOID DumpListOfExport(VOID *lib) {

    IMAGE_DOS_HEADER* MZ = (IMAGE_DOS_HEADER*)lib;
    IMAGE_NT_HEADERS* PE = (IMAGE_NT_HEADERS*)((BYTE*)lib + MZ->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)lib + PE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *name = (DWORD*)((BYTE*)lib + export->AddressOfNames);

    DWORD i = 0;
    for(i; i < export->NumberOfNames; i++) {
		    printf("%s\n",(CHAR*)lib + name[i]);
	  }    
}

int main (int argc, char **argv) {
    CHAR *dll = argv[1];
    HANDLE hDll = LoadLibrary(dll);
	
    printf("Loading %s\n", dll);
    if(hDll == NULL) {
        ExitProcess(0);
    }

	  DumpListOfExport(hDll);

    CloseHandle(hDll);
    return 0;
}
