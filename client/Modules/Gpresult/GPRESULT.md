# Gpresult — RSoP reporter BOF

A BOF that reimplements the useful core of `gpresult /R` without spawning
`gpresult.exe`. It queries the **RSoP (Resultant Set of Policy) WMI provider**
directly, plus a handful of WinAPI calls for the header.

## Why not just `shell gpresult /R`

`gpresult.exe` works, but it spawns a child process and its output is
text-scraped. This BOF pulls the same data straight from the RSoP WMI
provider (`root\rsop\user` / `root\rsop\computer`), which is the same source
`gpresult /R` reads — no child process, single buffered output chunk.

## Commands

```
gpresult             user + computer RSoP (matches gpresult /R)
gpresult user        user settings only
gpresult computer    computer settings only
```

## Data sources

### Header (WinAPI, once)
| Field | Source |
|---|---|
| Hostname | `GetComputerNameExA(ComputerNameDnsHostname)` |
| Domain | `GetComputerNameExA(ComputerNameDnsDomain)` |
| Domain controller | `DsGetDcNameA` → `DomainControllerName` (strips `\\`) |
| OS version | `RtlGetVersion` from `ntdll.dll` (GetVersionEx lies without a manifest) |
| OS configuration | `HKLM\...\ProductOptions\ProductType` (Workstation/Server/DC) |
| User DN | `GetUserNameExA(NameFullyQualifiedDN)` |
| Local profile | `%USERPROFILE%` |
| Domain type | DC's `Win32_OperatingSystem.Version` (best-effort label) |

### RSoP (WMI)
| Class | What it provides |
|---|---|
| `RSOP_Session` | `targetName`, `creationTime` (→ "Last applied"), `Site`, `slowLink`, `SecurityGroups[]` |
| `RSOP_GPO` | `name`, `enabled`, `filterAllowed`, `accessDenied` → applied vs filtered-out GPOs |
| `RSOP_ExtensionStatus` | (available, not currently printed) |

Security groups are `string[]` of SIDs; each is resolved to a friendly
`DOMAIN\Name` via `ConvertStringSidToSidA` + `LookupAccountSidA`, falling
back to the raw SID.

## Build

```
x86_64-w64-mingw32-g++ -c -Os -w -mno-stack-arg-probe \
    src/entry.cpp -I include -o bin/gpresult.x64.o
```

- g++ (wbemcli.h COM), `-mno-stack-arg-probe` avoids `___chkstk_ms`.
- Every WMI string is a real `BSTR` via `SysAllocString`/`SysFreeString`.
- Output is buffered via `bprintf()` and flushed in one `BeaconOutput`.

## Undefined-symbol contract

`nm -u` must show only `__imp_*` imports. Verified clean — no `___chkstk_ms`,
no `MSVCRT$`-beyond-declared, no mangled `_Z*` names.

## Notes / limitations

- RSoP logging-mode data only exists if Group Policy has been applied to the
  target (or `gpresult /R` has run once) in the beacon's session. If
  `RSOP_Session` is empty, the BOF reports it clearly.
- Computer settings are available to any local user; **user** settings require
  the RSoP user namespace, which reflects the beacon process's security
  context (so run it in the target user's session for user data).
- The remote `root\cimv2` query for domain functional level is best-effort;
  it prints `Unknown` if the DC is unreachable.
