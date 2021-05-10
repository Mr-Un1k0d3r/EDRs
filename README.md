# EDRs

This repo contains information about EDRs that can be useful during red team exercise.


# patch_syscall_dynamically64.c

This proof-of-concept is resolving the syscall ID dynamically no need to check the version running on the remote host. To get the information on disk (not tampered) a call to `CreateFileMapping` and `MapViewOfFile` Windows APIs is performed. The DLL is then parsed to retrived the data and used to patch the live code.

# patch_syscall64.c

This proof-of-concept is patch the syscall ID specified in the code. The live version of the DLL is then patched using the hardcoded syscall ID and reverted to the original unpatched state.

# get_syscall64.c

This utility is used to retrived the sycall ID associated with a Windows API.

```
get_syscall64.exe ntdll.dll NtOpenProcess

ntdll.dll!NtOpenProcess at 0x00007FF873F6CAD0
NtOpenProcess syscall ID 0x00000026 (38)
```

# Excel version of the list of hooks

[EDRs.xlsx formatted by Vincent Yiu](https://github.com/Mr-Un1k0d3r/EDRs/blob/main/EDRs.xlsx)

# Markdown version of the list of hooks

[EDRs.md formatted by Vincent Yiu](https://github.com/Mr-Un1k0d3r/EDRs/blob/main/EDRs.md)

# EDRs Hooked APIs

Want to contribute simply run `hook_finder64.exe C:\windows\system32\ntdll.dll` and submit the output.

### CrowdStrike hooked ntdll.dll APIs

[CrowdStrike hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/crowdstrike.txt)

### SentinelOne hooked ntdll.dll APIs

[SentinelOne hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/sentinelone.txt)

### Cylance hooked ntdll.dll APIs (Thanks to Seemant Bisht)

[Cylance hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/cylance.txt)

### Sophos hooked ntdll.dll APIs

[Sophos hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/sophos.txt)

### Attivo Deception hooked ntdll.dll APIs

[Attivo hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/attivo.txt)

### CarbonBlack hooked ntdll.dll APIs (Thanks to Hackndo)

[CarbonBlack hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/carbonblack.txt)

### Symantec hooked ntdll.dll APIs (Thanks to CarsonSallis)

[Symantec hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/symantec.txt)

### DeepInstinct hooked ntdll.dll APIs (Thanks to P0chAcc0)

[DeepInstinct hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/deepinstinct.txt)

### Morphises hooked ntdll.dll APIs

[Morphisec hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/morphisec.txt)

### McAfee hooked ntdll.dll APIs

[McAfee hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/mcafee.txt)

### Cortex XDR hooked APIs (KERNEL MODE)

:warning: These hooks are set kernel mode. They can't be unhooked from the user mode

[Cortex XDR hooks list](https://raw.githubusercontent.com/Mr-Un1k0d3r/EDRs/main/cortex.txt)

## Credit

Mr.Un1k0d3r RingZer0 Team
