|                                          | Attivo | Carbon Black | CrowdStrike | Cylance | Deep Instinct | Morphisec | Sentinel One | Sophos | Symantec |
|------------------------------------------|--------|--------------|-------------|---------|---------------|-----------|--------------|--------|----------|
| KiUserApcDispatcher                      |        |              |             |         |               | TRUE      | TRUE         | TRUE   |          |
| KiUserExceptionDispatcher                |        |              |             |         |               | TRUE      |              |        |          |
| LdrFindEntryForAddress                   |        |              |             |         |               | TRUE      |              |        |          |
| LdrLoadDll                               |        |              |             |         |               |           | TRUE         | TRUE   |          |
| LdrOpenImageFileOptionsKey               | TRUE   |              |             |         |               |           |              |        |          |
| LdrResolveDelayLoadedAPI                 |        |              |             |         |               | TRUE      |              |        |          |
| NtAlertResumeThread                      |        |              |             |         | TRUE          |           |              |        |          |
| NtAllocateVirtualMemory                  |        | TRUE         | TRUE        | TRUE    |               |           | TRUE         | TRUE   |          |
| NtAllocateVirtualMemoryEx                |        |              | TRUE        |         |               |           |              |        |          |
| NtAlpcConnectPort                        |        |              |             |         |               |           |              | TRUE   |          |
| NtAreMappedFilesTheSame                  |        |              |             |         |               | TRUE      |              |        |          |
| NtClose                                  |        | TRUE         |             |         | TRUE          |           |              |        |          |
| NtCreateFile                             |        | TRUE         |             |         |               |           |              |        | TRUE     |
| NtCreateKey                              |        |              |             |         |               |           |              |        | TRUE     |
| NtCreateProcess                          |        |              |             | TRUE    | TRUE          |           |              |        |          |
| NtCreateProcessEx                        | TRUE   |              |             | TRUE    | TRUE          |           |              |        |          |
| NtCreateSection                          | TRUE   |              |             |         | TRUE          |           |              |        |          |
| NtCreateThread                           |        | TRUE         |             | TRUE    |               |           |              |        |          |
| NtCreateThreadEx                         |        | TRUE         |             | TRUE    | TRUE          |           | TRUE         |        |          |
| NtCreateUserProcess                      |        |              |             | TRUE    |               |           | TRUE         |        | TRUE     |
| NtDeleteFile                             |        |              |             |         |               |           |              |        | TRUE     |
| NtDeleteKey                              |        |              |             |         |               |           |              |        | TRUE     |
| NtDeleteValueKey                         |        |              |             |         |               |           |              |        | TRUE     |
| NtDeviceIoControlFile                    |        |              | TRUE        |         |               |           |              |        |          |
| NtDuplicateObject                        |        |              |             |         | TRUE          |           |              |        |          |
| NtFreeVirtualMemory                      |        |              |             | TRUE    |               |           | TRUE         | TRUE   |          |
| NtGetContextThread                       |        |              | TRUE        |         |               |           |              |        |          |
| NtLoadDriver                             |        |              |             |         |               |           | TRUE         |        |          |
| NtMapUserPhysicalPages                   |        |              |             |         |               |           | TRUE         |        |          |
| NtMapViewOfSection                       |        | TRUE         | TRUE        | TRUE    | TRUE          | TRUE      | TRUE         | TRUE   | TRUE     |
| NtMapViewOfSectionEx                     |        |              | TRUE        |         |               |           |              |        |          |
| NtOpenFile                               |        |              |             |         |               |           |              |        | TRUE     |
| NtOpenKey                                |        |              |             |         |               |           |              |        | TRUE     |
| NtOpenKeyEx                              |        |              |             |         |               |           |              |        | TRUE     |
| NtOpenProcess                            | TRUE   | TRUE         |             |         |               |           | TRUE         | TRUE   |          |
| NtProtectVirtualMemory                   | TRUE   | TRUE         | TRUE        | TRUE    |               |           | TRUE         |        |          |
| NtQueryAttributesFile                    |        |              |             |         |               | TRUE      |              |        |          |
| NtQueryFullAttributesFile                |        |              |             |         |               | TRUE      |              |        |          |
| NtQueryInformationProcess                |        | TRUE         |             |         |               |           |              |        |          |
| NtQueryInformationThread                 |        |              | TRUE        |         |               |           |              |        |          |
| NtQuerySystemInformation                 |        | TRUE         |             |         |               |           | TRUE         |        |          |
| NtQuerySystemInformationEx               |        |              |             |         |               |           | TRUE         |        |          |
| NtQueryVirtualMemory                     |        |              |             |         |               | TRUE      |              |        |          |
| NtQueueApcThread                         |        | TRUE         | TRUE        | TRUE    | TRUE          | TRUE      | TRUE         |        |          |
| NtQueueApcThreadEx                       |        | TRUE         | TRUE        | TRUE    |               |           | TRUE         |        |          |
| NtReadVirtualMemory                      | TRUE   | TRUE         | TRUE        | TRUE    |               |           | TRUE         |        |          |
| NtRenameKey                              |        |              |             |         |               |           |              |        | TRUE     |
| NtResumeThread                           |        |              | TRUE        |         | TRUE          |           | TRUE         |        |          |
| NtSetContextThread                       |        |              | TRUE        |         | TRUE          |           | TRUE         | TRUE   |          |
| NtSetInformationFile                     |        |              |             |         |               |           |              |        | TRUE     |
| NtSetInformationProcess                  |        |              | TRUE        | TRUE    |               |           | TRUE         |        |          |
| NtSetInformationThread                   |        |              | TRUE        |         |               |           | TRUE         |        |          |
| NtSetValueKey                            |        |              |             |         |               |           |              |        | TRUE     |
| NtSuspendThread                          |        |              | TRUE        |         |               |           |              |        |          |
| NtTerminateProcess                       | TRUE   |              |             |         |               |           | TRUE         |        | TRUE     |
| NtTerminateThread                        |        |              |             |         |               |           |              |        | TRUE     |
| NtUnmapViewOfSection                     |        | TRUE         | TRUE        | TRUE    |               |           | TRUE         | TRUE   |          |
| NtUnmapViewOfSectionEx                   |        |              | TRUE        |         |               |           |              |        |          |
| NtWriteFile                              |        | TRUE         |             |         |               |           |              |        |          |
| NtWriteVirtualMemory                     | TRUE   | TRUE         | TRUE        | TRUE    | TRUE          |           | TRUE         | TRUE   |          |
| RtlAddVectoredExceptionHandler           |        |              |             |         |               |           | TRUE         |        |          |
| RtlDosApplyFileIsolationRedirection_Ustr |        |              |             |         |               | TRUE      |              |        |          |
| RtlGetNativeSystemInformation            |        | TRUE         |             |         |               |           | TRUE         |        |          |
| RtlInstallFunctionTableCallback          |        |              |             |         |               |           |              | TRUE   |          |
| ZwAlertResumeThread                      |        |              |             |         | TRUE          |           |              |        |          |
| ZwAllocateVirtualMemory                  |        | TRUE         | TRUE        | TRUE    |               |           | TRUE         | TRUE   |          |
| ZwAllocateVirtualMemoryEx                |        |              | TRUE        |         |               |           |              |        |          |
| ZwAlpcConnectPort                        |        |              |             |         |               |           |              | TRUE   |          |
| ZwAreMappedFilesTheSame                  |        |              |             |         |               | TRUE      |              |        |          |
| ZwClose                                  |        | TRUE         |             |         | TRUE          |           |              |        |          |
| ZwCreateFile                             |        | TRUE         |             |         |               |           |              |        | TRUE     |
| ZwCreateKey                              |        |              |             | TRUE    |               |           |              |        | TRUE     |
| ZwCreateProcess                          |        |              |             | TRUE    | TRUE          |           |              |        |          |
| ZwCreateProcessEx                        | TRUE   |              |             |         | TRUE          |           |              |        |          |
| ZwCreateSection                          | TRUE   |              |             |         | TRUE          |           |              |        |          |
| ZwCreateThread                           |        | TRUE         |             | TRUE    |               |           |              |        |          |
| ZwCreateThreadEx                         |        | TRUE         |             | TRUE    | TRUE          |           | TRUE         |        |          |
| ZwCreateUserProcess                      |        |              |             | TRUE    |               |           | TRUE         |        | TRUE     |
| ZwDeleteFile                             |        |              |             |         |               |           |              |        | TRUE     |
| ZwDeleteKey                              |        |              |             |         |               |           |              |        | TRUE     |
| ZwDeleteValueKey                         |        |              |             |         |               |           |              |        | TRUE     |
| ZwDeviceIoControlFile                    |        |              | TRUE        |         |               |           |              |        |          |
| ZwDuplicateObject                        |        |              |             |         | TRUE          |           |              |        |          |
| ZwFreeVirtualMemory                      |        |              |             | TRUE    |               |           | TRUE         | TRUE   |          |
| ZwGetContextThread                       |        |              | TRUE        |         |               |           |              |        |          |
| ZwLoadDriver                             |        |              |             |         |               |           | TRUE         |        |          |
| ZwMapUserPhysicalPages                   |        |              |             |         |               |           | TRUE         |        |          |
| ZwMapViewOfSection                       |        | TRUE         | TRUE        | TRUE    | TRUE          | TRUE      | TRUE         | TRUE   | TRUE     |
| ZwMapViewOfSectionEx                     |        |              | TRUE        |         |               |           |              |        |          |
| ZwOpenFile                               |        |              |             |         |               |           |              |        | TRUE     |
| ZwOpenKey                                |        |              |             |         |               |           |              |        | TRUE     |
| ZwOpenKeyEx                              |        |              |             |         |               |           |              |        | TRUE     |
| ZwOpenProcess                            | TRUE   | TRUE         |             |         |               |           | TRUE         |        |          |
| ZwProtectVirtualMemory                   | TRUE   | TRUE         | TRUE        | TRUE    |               |           | TRUE         | TRUE   |          |
| ZwQueryAttributesFile                    |        |              |             |         |               | TRUE      |              |        |          |
| ZwQueryFullAttributesFile                |        |              |             |         |               | TRUE      |              |        |          |
| ZwQueryInformationProcess                |        | TRUE         |             |         |               |           |              |        |          |
| ZwQueryInformationThread                 |        |              | TRUE        |         |               |           |              |        |          |
| ZwQuerySystemInformation                 |        | TRUE         |             |         |               |           | TRUE         |        |          |
| ZwQuerySystemInformationEx               |        |              |             |         |               |           | TRUE         |        |          |
| ZwQueryVirtualMemory                     |        |              |             |         |               | TRUE      |              |        |          |
| ZwQueueApcThread                         |        | TRUE         | TRUE        | TRUE    | TRUE          | TRUE      | TRUE         | TRUE   |          |
| ZwQueueApcThreadEx                       |        | TRUE         | TRUE        | TRUE    |               |           | TRUE         |        |          |
| ZwReadVirtualMemory                      | TRUE   | TRUE         | TRUE        | TRUE    |               |           | TRUE         | TRUE   |          |
| ZwRenameKey                              |        |              |             |         |               |           |              |        | TRUE     |
| ZwResumeThread                           |        |              | TRUE        |         | TRUE          |           | TRUE         |        |          |
| ZwSetContextThread                       |        |              | TRUE        |         | TRUE          |           | TRUE         | TRUE   |          |
| ZwSetInformationFile                     |        |              |             |         |               |           |              |        | TRUE     |
| ZwSetInformationProcess                  |        |              | TRUE        | TRUE    |               |           | TRUE         |        |          |
| ZwSetInformationThread                   |        |              | TRUE        |         |               |           | TRUE         |        |          |
| ZwSetValueKey                            |        |              |             |         |               |           |              |        | TRUE     |
| ZwSuspendThread                          |        |              | TRUE        |         |               |           |              |        |          |
| ZwTerminateProcess                       | TRUE   |              |             |         |               |           | TRUE         |        | TRUE     |
| ZwTerminateThread                        |        |              |             |         |               |           |              |        | TRUE     |
| ZwUnmapViewOfSection                     |        |              | TRUE        | TRUE    |               |           | TRUE         | TRUE   |          |
| ZwUnmapViewOfSectionEx                   |        |              | TRUE        |         |               |           |              |        |          |
| ZwWriteFile                              |        | TRUE         |             |         |               |           |              |        |          |
| ZwWriteVirtualMemory                     | TRUE   | TRUE         | TRUE        | TRUE    | TRUE          |           | TRUE         | TRUE   |          |
