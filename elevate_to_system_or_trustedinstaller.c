#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

DWORD GetProcByPID(CHAR *name);
DWORD GetTrustedInstallerPID();
BOOL ImpersonateByPID(DWORD PID, HANDLE *hStorage);
BOOL ElevateSystem();
BOOL ElevateTrustedInstaller();

HANDLE hTokenSystem = NULL;
HANDLE hTokenTrustedInstaller = NULL;
BOOL bSpawnAsTrusted = FALSE;

DWORD GetProcByPID(CHAR *name) {
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

BOOL ElevateSystem() {
    DWORD PID = GetProcByPID("winlogon.exe");
    if(ImpersonateByPID(PID, &hTokenSystem)) {
        printf("[%s] ImpersonateByPID(SYSTEM) succeeded.\n", __func__);
    }
}

BOOL ElevateTrustedInstaller() {
    DWORD PID = GetTrustedInstallerPID();
    if(ImpersonateByPID(PID, &hTokenTrustedInstaller)) {
        printf("[%s] ImpersonateByPID(TrustedInstaller) succeeded.\n", __func__);
    }
}

VOID CreateProcessImpersonate(HANDLE hToken, CHAR *command) {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    GetStartupInfoW(&si);
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    DWORD dwSize = MultiByteToWideChar(CP_ACP, 0, command, -1, NULL, 0);
    printf("[%s] MultiByteToWideChar need %d bytes.\n", __func__, dwSize);
    WCHAR wCommand[dwSize];
    MultiByteToWideChar(CP_ACP, 0, command, -1, (LPWSTR)wCommand, dwSize);

    BOOL bResult = CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL, wCommand, CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi);

    if(!bResult) {
        printf("[%s] CreateProcessWithTokenW with argument '%ls'. Error: %d\n", __func__, wCommand, GetLastError());
    }
}

int main(int argc, char **argv) {
    
    ElevateSystem();
    if(argc >= 2) {
        if(strcmp(argv[1], "trusted") == 0) {
            bSpawnAsTrusted = TRUE;
            ElevateTrustedInstaller();
        }
    }

    printf("[%s] (SYSTEM) Token HANDLE 0x%p.\n", __func__, hTokenSystem);
    printf("[%s] (TrustedInstaller) Token HANDLE 0x%p.\n", __func__, hTokenTrustedInstaller);

    if(bSpawnAsTrusted) {
        CreateProcessImpersonate(hTokenTrustedInstaller, "cmd.exe");
    } else {
        CreateProcessImpersonate(hTokenSystem, "cmd.exe");
    }

    if(hTokenSystem != NULL) {
        CloseHandle(hTokenSystem);
    }
    if(hTokenTrustedInstaller != NULL) {
        CloseHandle(hTokenTrustedInstaller);
    }

    return 0;
}
