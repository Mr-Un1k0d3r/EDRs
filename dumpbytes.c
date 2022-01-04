#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

VOID ListLoadedDlls() {

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    printf("Listing loaded modules inside process PID %d\n------------------------------------------\n", GetCurrentProcessId());
    if(Module32First(hSnap, &me32)) {
        do {
            printf("%s is loaded at 0x%p.\n", me32.szExePath, me32.modBaseAddr);

        } while(Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);
}

int main(int argc, char **argv) {
		
	DWORD dwSize = atoi(argv[1]);
	CHAR *dll = argv[2];
	CHAR *func = argv[3];
	
	FARPROC ptr = GetProcAddress(LoadLibrary(dll),func);
	printf("%s!%s found at 0x%p\n", dll, func, ptr);
	
	CHAR *data = ptr;
	ListLoadedDlls();
	DWORD i = 0;
	for(i; i < dwSize; i++) {
		printf("%02x", (unsigned char)data[i]);
	}
	
	return 0;
}
