# EDRs

This repo contains information about EDRs that can be useful during red team exercise.

# CrowdStrike hooked ntdll.dll APIs

```
C:\Users\dev\Desktop>hook_finder_64.exe C:\Windows\System32\ntdll.dll
Loading C:\Windows\System32\ntdll.dll
------------------------------------------
BASE                    0x00007FFAE0030000      MZÉ
PE                      0x00007FFAE00300E8      PE
ExportTableOffset       0x00007FFAE01812A0
OffsetNameTable         0x00007FFAE01838C0
Function Counts         0x97e (2430)
------------------------------------------
NtAllocateVirtualMemory is hooked
NtAllocateVirtualMemoryEx is hooked
NtDeviceIoControlFile is hooked
NtGetContextThread is hooked
NtMapViewOfSection is hooked
NtMapViewOfSectionEx is hooked
NtProtectVirtualMemory is hooked
NtQueryInformationThread is hooked
NtQueueApcThread is hooked
NtQueueApcThreadEx is hooked
NtReadVirtualMemory is hooked
NtResumeThread is hooked
NtSetContextThread is hooked
NtSetInformationProcess is hooked
NtSetInformationThread is hooked
NtSuspendThread is hooked
NtUnmapViewOfSection is hooked
NtUnmapViewOfSectionEx is hooked
NtWriteVirtualMemory is hooked
ZwAllocateVirtualMemory is hooked
ZwAllocateVirtualMemoryEx is hooked
ZwDeviceIoControlFile is hooked
ZwGetContextThread is hooked
ZwMapViewOfSection is hooked
ZwMapViewOfSectionEx is hooked
ZwProtectVirtualMemory is hooked
ZwQueryInformationThread is hooked
ZwQueueApcThread is hooked
ZwQueueApcThreadEx is hooked
ZwReadVirtualMemory is hooked
ZwResumeThread is hooked
ZwSetContextThread is hooked
ZwSetInformationProcess is hooked
ZwSetInformationThread is hooked
ZwSuspendThread is hooked
ZwUnmapViewOfSection is hooked
ZwUnmapViewOfSectionEx is hooked
ZwWriteVirtualMemory is hooked
------------------------------------------
Completed
```
# SentinelOne hooked ntdll.dll APIs

```
C:\Users\dev\Desktop>generic_hook_finder_64.exe C:\windows\system32\ntdll.dll
Loading C:\windows\system32\ntdll.dll
------------------------------------------
BASE                    0x00007FF8EDA30000      MZÉ
PE                      0x00007FF8EDA300E8      PE
ExportTableOffset       0x00007FF8EDB812A0
OffsetNameTable         0x00007FF8EDB838C0
Functions Count         0x97e (2430)
------------------------------------------
KiUserApcDispatcher is hooked
LdrLoadDll is hooked
NtAllocateVirtualMemory is hooked
NtCreateThreadEx is hooked
NtCreateUserProcess is hooked
NtFreeVirtualMemory is hooked
NtLoadDriver is hooked
NtMapUserPhysicalPages is hooked
NtMapViewOfSection is hooked
NtOpenProcess is hooked
NtProtectVirtualMemory is hooked
NtQuerySystemInformation is hooked
NtQuerySystemInformationEx is hooked
NtQueueApcThread is hooked
NtQueueApcThreadEx is hooked
NtReadVirtualMemory is hooked
NtResumeThread is hooked
NtSetContextThread is hooked
NtSetInformationProcess is hooked
NtSetInformationThread is hooked
NtTerminateProcess is hooked
NtUnmapViewOfSection is hooked
NtWriteVirtualMemory is hooked
RtlAddVectoredExceptionHandler is hooked
RtlGetNativeSystemInformation is hooked
ZwAllocateVirtualMemory is hooked
ZwCreateThreadEx is hooked
ZwCreateUserProcess is hooked
ZwFreeVirtualMemory is hooked
ZwLoadDriver is hooked
ZwMapUserPhysicalPages is hooked
ZwMapViewOfSection is hooked
ZwOpenProcess is hooked
ZwProtectVirtualMemory is hooked
ZwQuerySystemInformation is hooked
ZwQuerySystemInformationEx is hooked
ZwQueueApcThread is hooked
ZwQueueApcThreadEx is hooked
ZwReadVirtualMemory is hooked
ZwResumeThread is hooked
ZwSetContextThread is hooked
ZwSetInformationProcess is hooked
ZwSetInformationThread is hooked
ZwTerminateProcess is hooked
ZwUnmapViewOfSection is hooked
ZwWriteVirtualMemory is hooked
------------------------------------------
Completed
```

# Cylance hooked ntdll.dll APIs (Thanks to Seemant Bisht)

```
C:\Users\dev\Desktop>generic_hook_finder_64.exe C:\windows\system32\ntdll.dll
Loading C:\windows\system32\ntdll.dll
------------------------------------------
BASE                    0x00007FF8841E0000      MZÉ
PE                      0x00007FF8841E00E0      PE
ExportTableOffset       0x00007FF88432BBB0
OffsetNameTable         0x00007FF88432E0D0
Functions Count         0x93e (2366)
------------------------------------------
NtAllocateVirtualMemory is hooked
NtCreateProcess is hooked
NtCreateProcessEx is hooked
NtCreateThread is hooked
NtCreateThreadEx is hooked
NtCreateUserProcess is hooked
NtFreeVirtualMemory is hooked
NtMapViewOfSection is hooked
NtProtectVirtualMemory is hooked
NtQueueApcThread is hooked
NtQueueApcThreadEx is hooked
NtReadVirtualMemory is hooked
NtSetInformationProcess is hooked
NtUnmapViewOfSection is hooked
NtWriteVirtualMemory is hooked
ZwAllocateVirtualMemory is hooked
ZwCreateProcess is hooked
ZwCreateProcessEx is hooked
ZwCreateThread is hooked
ZwCreateThreadEx is hooked
ZwCreateUserProcess is hooked
ZwFreeVirtualMemory is hooked
ZwMapViewOfSection is hooked
ZwProtectVirtualMemory is hooked
ZwQueueApcThread is hooked
ZwQueueApcThreadEx is hooked
ZwReadVirtualMemory is hooked
ZwSetInformationProcess is hooked
ZwUnmapViewOfSection is hooked
ZwWriteVirtualMemory is hooked
------------------------------------------
Completed
```

# Sophos hooked ntdll.dll APIs

```
C:\Users\dev\Desktop>hook_finder_64.exe C:\Windows\System32\ntdll.dll
Loading C:\Windows\System32\ntdll.dll
------------------------------------------
BASE                    0x00007FFEBDB10000      MZÉ
PE                      0x00007FFEBDB100E8      PE
ExportTableOffset       0x00007FFEBDC612A0
OffsetNameTable         0x00007FFEBDC638C0
Functions Count         0x97e (2430)
------------------------------------------
KiUserApcDispatcher is hooked
LdrLoadDll is hooked
NtAllocateVirtualMemory is hooked
NtAlpcConnectPort is hooked
NtFreeVirtualMemory is hooked
NtMapViewOfSection is hooked
NtProtectVirtualMemory is hooked
NtQueueApcThread is hooked
NtReadVirtualMemory is hooked
NtSetContextThread is hooked
NtUnmapViewOfSection is hooked
NtWriteVirtualMemory is hooked
RtlInstallFunctionTableCallback is hooked
ZwAllocateVirtualMemory is hooked
ZwAlpcConnectPort is hooked
ZwFreeVirtualMemory is hooked
ZwMapViewOfSection is hooked
ZwProtectVirtualMemory is hooked
ZwQueueApcThread is hooked
ZwReadVirtualMemory is hooked
ZwSetContextThread is hooked
ZwUnmapViewOfSection is hooked
ZwWriteVirtualMemory is hooked
------------------------------------------
Completed
```
