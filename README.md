# dAnSR

C# Tool to enumerate Attack Surface Reduction (ASR) rules and dump lsass via rule whitelists

## Motivation
To speed up ASR enumeration and credential dumping for internal pentests, this tool can be used so that no C2 magic is required (e.g. spawning an implant and `spawnto mrt.exe` just to dump lsass).

## Usage
```
Usage: dAnSR.exe [options]
Options:
  enum   - Enumerate configured ASR rules and exclusions
  dump   - Dump lsass via MiniDumpWriteDump
  auto   - Copy dAnSR to C:\Users\<user>\AppData\Local\Temp\Ctx-*\Extract\TrolleyExpress.exe and dump lsass (ASR bypass)

Note: Rename this binary to automatically dump lsass upon execution (no arg mode)
```

If the rule `Block credential stealing from the Windows local security authority subsystem (lsass.exe)` is found to be activated (`enum`), creds can be dumped by using `.\dAnSR.exe auto` :D

## How it works
### ASR Enumeration
The WMI namespace `\\.\root\Microsoft\Windows\Defender` contains the `MSFT_MpPreference` object, where information about all configured ASR rules are stored. Accessing this information does not require local admin privs.

### Credz
The lsass ASR rule contains several hard-coded whitelisted paths, including `%temp%\\Ctx-*\\Extract\\TrolleyExpress.exe`. Thus, we can simply create the necessary directory structure, copy ourselves to `TrolleyExpress.exe` and dump lsass. A decompiled version of the ASR rules and more whitelisted paths can be found in this repo: https://github.com/HackingLZ/ExtractedDefender

To dump lsass, the WinAPI `MiniDumpWriteDump` is used in order to create a dumpfile of the process. This file is then compressed into a gzip archive to lower the detection rate of the dump on disk.

### OpSec
This tool does not implement any opsec features such as AMSI or ETW bypasses, HWBP or (in)direct syscalls.

## Mitigations
- Make sure LSASS is configured with RunAsPPL
- Enable Credential Guard to protect secrets with virtualization-based security (VBS)
