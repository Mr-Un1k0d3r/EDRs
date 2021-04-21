#include <Windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    HANDLE hLib = LoadLibraryA(argv[1]);
    CHAR *ptr = (CHAR*)GetProcAddress(hLib, argv[2]);
    DWORD syscall = 0;
    printf("%s!%s at 0x%p\n", argv[1], argv[2], ptr);
    printf("%s syscall ID 0x%08x (%d)\n", argv[2], (DWORD)*(ptr + 4), (DWORD)*(ptr + 4));
    return 0;
}
