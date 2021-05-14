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

int main() {
    ListLoadedDlls();
    return 0;
}
