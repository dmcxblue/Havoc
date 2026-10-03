# UacCheck — UAC Bypass Feasibility Checker

A recon-only BOF that determines which [UAC-BOF-Bonanza](https://github.com/icyguider/UAC-BOF-Bonanza) bypasses would succeed on a target **without executing any of them**. Run `uac-check all` before committing to a bypass technique.

## How It Works

UacCheck gathers the target's environment once (OS version, UAC policy, token state), then evaluates each technique's specific preconditions. It reports `[+] VIABLE` with the exact `uac-bypass` command to use, or `[-] NOT VIABLE` with the reason.

### Architecture

```
uac-check.py  ──(mode int)──>  entry.c (BOF)
                                  │
                                  ├── GatherEnvironment()     ← runs once
                                  │     ├── RtlGetVersion     ← OS build
                                  │     ├── Registry read     ← UAC policy
                                  │     └── Token query       ← integrity + groups
                                  │
                                  └── Check<Technique>()      ← per bypass
                                        ├── File existence
                                        ├── Registry key access
                                        ├── COM CLSID presence
                                        └── Build-number gates
```

### Wire Protocol

Single integer packed by the Python wrapper via the shared `Packer` class:

| Mode | Subcommand      | What it checks                              |
|------|-----------------|---------------------------------------------|
| 0    | `all`           | Environment info + all 7 technique checks   |
| 1    | `env`           | Environment info only                       |
| 2    | `trustedpath`   | TrustedPathDLLHijack preconditions           |
| 3    | `silentcleanup` | SilentCleanupWinDir preconditions            |
| 4    | `sspidatagram`  | SSPI Datagram Contexts preconditions         |
| 5    | `registrycommand` | ms-settings Shell\\Open\\command hijack    |
| 6    | `elevatedcom`   | CmstpElevatedCOM (ICMLuaUtil) preconditions |
| 7    | `colordataproxy` | ColorDataProxy + ICMLuaUtil preconditions   |
| 8    | `editionupgrade` | EditionUpgradeManager COM preconditions     |

## Detailed Code Walkthrough

### 1. Environment Gathering (`GatherEnvironment`)

Every technique check depends on the same baseline context. `GatherEnvironment` collects it once into a `UAC_ENV` struct:

#### OS Version — `RtlGetVersion`

```c
typedef LONG (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);

HMODULE hNtdll = KERNEL32$LoadLibraryA("ntdll.dll");
pRtlGetVersion fnVer = (pRtlGetVersion)KERNEL32$GetProcAddress(hNtdll, "RtlGetVersion");
RTL_OSVERSIONINFOW vi = {0};
vi.dwOSVersionInfoSize = sizeof(vi);
fnVer(&vi);  // → env->dwMajor, dwMinor, dwBuild
```

We use `RtlGetVersion` instead of `GetVersionEx` because Microsoft's compatibility shims cause `GetVersionEx` to lie about the OS version unless the calling binary has a proper manifest. `RtlGetVersion` always returns the true version. The function is loaded dynamically from `ntdll.dll` via `GetProcAddress` because BOFs can't link against ntdll exports that aren't in the DFR headers.

The build number is critical — several techniques only work on specific Windows 10 versions:
- **Build 15063** (1703): fodhelper.exe introduced → `registrycommand`
- **Build 17134** (1803): Required for `sspidatagram`, `colordataproxy`, `editionupgrade`
- **Build 22000** (Win11): May have patched `trustedpath`

#### UAC Registry Settings

```c
ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE,
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    0, KEY_QUERY_VALUE, &hKey);
ADVAPI32$RegQueryValueExA(hKey, "EnableLUA", ...);
ADVAPI32$RegQueryValueExA(hKey, "ConsentPromptBehaviorAdmin", ...);
```

Two values from `HKLM\...\Policies\System`:

- **EnableLUA** (default 1): If 0, UAC is disabled entirely and all processes run elevated — no bypass needed.
- **ConsentPromptBehaviorAdmin** (default 5): Controls the consent prompt behavior. Value 0 means "elevate without prompting" (effectively no UAC for admins). Values 1-5 mean some form of prompt exists, which is what bypasses circumvent.

#### Token Integrity Level

```c
ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, ...);
PUCHAR pCount = ADVAPI32$GetSidSubAuthorityCount(pTIL->Label.Sid);
PDWORD pLevel = ADVAPI32$GetSidSubAuthority(pTIL->Label.Sid, *pCount - 1);
// pLevel values:
//   0x0000 = Untrusted, 0x1000 = Low, 0x2000 = Medium,
//   0x3000 = High,      0x4000 = System
```

The integrity level determines whether UAC has already filtered the token:
- **Medium** (0x2000): The standard filtered token for a local admin. This is where UAC bypasses apply.
- **High** (0x3000): Already elevated — bypass not needed.
- **System** (0x4000): Running as SYSTEM — bypass not needed.

#### Admin Group Membership

```c
ADVAPI32$AllocateAndInitializeSid(&NtAuthority, 2,
    SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
    ..., &pAdminSid);

// Walk TokenGroups and match with EqualSid
ADVAPI32$GetTokenInformation(hToken, TokenGroups, pGroups, ...);
for (gi = 0; gi < pGroups->GroupCount; gi++) {
    if (ADVAPI32$EqualSid(pAdminSid, pGroups->Groups[gi].Sid)) {
        env->bIsAdmin = TRUE;
        break;
    }
}
```

We deliberately use `GetTokenInformation(TokenGroups)` + `EqualSid` instead of `CheckTokenMembership`. This is critical for UAC bypass detection:

On a UAC-filtered token, the `BUILTIN\Administrators` SID is present in the token groups but marked `SE_GROUP_USE_FOR_DENY_ONLY` (disabled). `CheckTokenMembership` returns FALSE for disabled group SIDs — which is technically correct for "can this token use admin privileges right now" but **wrong** for our purpose of "is this user a local admin who could benefit from a UAC bypass."

The whole point of UAC bypasses is that the admin SID exists in the token but is disabled by UAC filtering. `EqualSid` finds the SID regardless of its attributes, correctly identifying the filtered-admin scenario.

Note: PrivKit uses `CheckTokenMembership(NULL, ...)` for its service DACL checks, which is correct there — it needs to know if the current token can *actively use* a SID for access checks. Here the question is different: does the SID exist at all?

UAC bypasses only work when:
1. The user IS a local admin (has the admin SID in their token groups, even if disabled)
2. The process is NOT elevated (medium integrity — filtered token)
3. UAC IS enabled (EnableLUA = 1)

This is the "medium-integrity admin with UAC" scenario — the filtered token that Windows gives to admin users by default.

### 2. Baseline Eligibility (`CanBypass`)

```c
static BOOL CanBypass(UAC_ENV *env) {
    return env->dwEnableLUA && env->bIsAdmin && !env->bIsElevated;
}
```

Every technique check calls this first. If false, the check short-circuits with a clear reason:
- Already elevated → "not needed"
- UAC disabled → "not needed"
- Not admin → "will not work"

### 3. Per-Technique Checks

#### TrustedPathDLLHijack (mode 2)

**Technique**: Creates a directory `C:\Windows \System32\` (note the trailing space in "Windows "). Windows trusts paths under `C:\Windows\System32\` for auto-elevation, but the path parser doesn't strip trailing spaces. The BOF copies `ComputerDefaults.exe` there and drops a malicious `Secur32.dll` — when ComputerDefaults auto-elevates from the trusted-looking path, it loads the attacker DLL.

**Preconditions checked**:
- `ComputerDefaults.exe` exists at `%SystemRoot%\System32\ComputerDefaults.exe`
- OS build warning for Win11 (build 22000+) where this may be patched

```c
BOOL bCompDef = FileExistsExpanded("%SystemRoot%\\System32\\ComputerDefaults.exe");
```

`FileExistsExpanded` uses `ExpandEnvironmentStringsA` to resolve `%SystemRoot%` before checking `GetFileAttributesA`. This handles non-standard Windows installations where the system root isn't `C:\Windows`.

#### SilentCleanupWinDir (mode 3)

**Technique**: The `SilentCleanup` scheduled task runs `%windir%\System32\cleanmgr.exe` elevated. By setting `HKCU\Environment\windir` to a controlled path, the attacker redirects where `%windir%` resolves to — the task runs the attacker's binary instead.

**Preconditions checked**:
- `HKCU\Environment` is writable (it's HKCU, so always should be for the current user)
- The `SilentCleanup` task exists in the TaskCache registry

```c
BOOL bTaskExists = HKLMKeyExists(
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
    "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup");
```

We check the registry tree path instead of using the Task Scheduler API because the registry check is lightweight and doesn't require COM initialization. The task's presence in TaskCache\Tree is sufficient — if it's there, it's registered.

#### SSPI Datagram Contexts (mode 4)

**Technique**: Abuses Windows SSPI authentication in datagram mode. The datagram context processing has a flaw where it returns an elevated token in certain conditions. This is a more complex, network-layer bypass.

**Preconditions checked**:
- OS build >= 17134 (Windows 10 1803). Earlier builds don't have the specific SSPI behavior this exploit targets.

This is the simplest check — it's primarily build-gated. No specific files or registry keys beyond the baseline eligibility.

#### RegistryShellCommand / fodhelper (mode 5)

**Technique**: `fodhelper.exe` is an auto-elevating Windows binary that reads its handler from `HKCU\Software\Classes\ms-settings\Shell\Open\command`. Since this registry path is under HKCU, any user can write to it. When fodhelper auto-elevates, it executes whatever command is in that key — with elevated privileges.

**Preconditions checked**:
- `fodhelper.exe` exists at `%SystemRoot%\System32\fodhelper.exe`
- `HKCU\Software\Classes\ms-settings\Shell\Open\command` is writable
- OS build >= 15063 (Windows 10 1703, when fodhelper was introduced)

```c
BOOL bCanWrite = CanWriteHKCUKey("Software\\Classes\\ms-settings\\Shell\\Open\\command");
```

`CanWriteHKCUKey` attempts to open the key with `KEY_SET_VALUE`. If the key doesn't exist yet (ERROR_FILE_NOT_FOUND), we return TRUE because HKCU keys can always be created by the current user.

#### CmstpElevatedCOM / ICMLuaUtil (mode 6)

**Technique**: `cmstp.exe` (Connection Manager Profile Installer) has an associated COM object (`CMSTPLUA`, CLSID `{3E5FC7F9-...}`) that supports the elevation moniker. The BOF instantiates this COM object with `CoCreateInstance` using `CLSCTX_LOCAL_SERVER` and the `Elevation:Administrator!new:` moniker. The `ICMLuaUtil` interface on this object has a `ShellExec` method that executes commands as elevated — no UAC prompt because cmstp.exe is in the auto-elevate whitelist.

**Preconditions checked**:
- `cmstp.exe` exists (it's the COM server for CMSTPLUA)
- The CMSTPLUA CLSID is registered in `HKLM\SOFTWARE\Classes\CLSID\{3E5FC7F9-...}`

#### ColorDataProxy + ICMLuaUtil (mode 7)

**Technique**: Two-stage attack. First, the `ColorDataProxy` COM object (CLSID `{D2E7025F-...}`) is used to write a file to a protected location (it runs as an elevated COM server). Then, `ICMLuaUtil::ShellExec` (same as elevatedcom) executes from that protected location.

**Preconditions checked**:
- `cmstp.exe` exists
- CMSTPLUA CLSID registered (for the ICMLuaUtil stage)
- ColorDataProxy CLSID `{D2E7025F-...}` registered (for the file-write stage)
- OS build >= 17134

#### EditionUpgradeManager COM (mode 8)

**Technique**: Similar to SilentCleanup's `%windir%` hijack but uses the `IEditionUpgradeManager` COM object (CLSID `{17CCA47D-...}`) instead of a scheduled task. This COM object auto-elevates and references `%windir%` — setting `HKCU\Environment\windir` redirects its execution.

**Preconditions checked**:
- `HKCU\Environment` is writable
- EditionUpgradeManager CLSID `{17CCA47D-...}` registered
- OS build >= 17134

### 4. BOF Integration Details

#### DFR (Dynamic Function Resolution)

The BOF uses the standard CS-Remote-OPs-BOF `bofdefs.h` for core DFR declarations and adds technique-specific DECLSPEC_IMPORT declarations at the top:

```c
DECLSPEC_IMPORT PUCHAR WINAPI ADVAPI32$GetSidSubAuthorityCount(PSID);
DECLSPEC_IMPORT PDWORD WINAPI ADVAPI32$GetSidSubAuthority(PSID, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AllocateAndInitializeSid(...);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$CheckTokenMembership(HANDLE, PSID, PBOOL);
```

These aren't in the shared `bofdefs.h` because they're specific to SID/token manipulation. The DECLSPEC_IMPORT attribute tells the BOF loader these are external symbols that need to be resolved at load time.

#### memcpy/memset Wrappers

```c
void *memcpy(void *dest, const void *src, size_t n) { return MSVCRT$memcpy(dest, src, n); }
void *memset(void *s, int c, size_t n)              { MSVCRT$memset(s, c, n); return s; }
```

Compiled with `-fno-builtin`, the compiler generates calls to `memcpy`/`memset` for struct initialization and copies. Without these wrappers, the BOF loader fails to resolve the bare symbols. The wrappers redirect to the DFR `MSVCRT$` versions.

#### Compilation

```bash
x86_64-w64-mingw32-gcc -o bin/uaccheck.x64.o \
    -c src/entry.c \
    -I ../../RemoteOps/CS-Remote-OPs-BOF/src/common \
    -DBOF -Os -fno-builtin
```

Flags:
- `-DBOF`: Activates the DFR declarations in `bofdefs.h` (the `#ifdef BOF` block)
- `-Os`: Optimize for size — BOFs should be small since they're transferred over C2
- `-fno-builtin`: Prevents GCC from replacing loops/copies with compiler built-in memset/memcpy that would fail to resolve in the BOF loader

## Usage

```
# Run all checks at once
uac-check all

# Environment info only (OS version, UAC settings, token state)
uac-check env

# Check a specific technique
uac-check trustedpath
uac-check silentcleanup
uac-check sspidatagram
uac-check registrycommand
uac-check elevatedcom
uac-check colordataproxy
uac-check editionupgrade
```

## Example Output

```
=== UAC Bypass Feasibility Check ===

[*] OS Version: 10.0 (Build 19045)
[*] EnableLUA: Yes (UAC active)
[*] ConsentPromptBehaviorAdmin: 5 (Prompt for consent for non-Windows binaries)
[*] Integrity Level: Medium
[*] Local Admin Group Member: Yes

[*] Bypass Eligibility: Medium-integrity admin with UAC — bypasses applicable

--- TrustedPathDLLHijack ---
[*] Technique: Create fake 'C:\Windows \System32\' (trailing space)
[*]   then drop a malicious Secur32.dll, execute ComputerDefaults.exe
[*] ComputerDefaults.exe present: Yes
[+] VIABLE -> uac-bypass trustedpath <local_dll>

--- SilentCleanupWinDir ---
[*] Technique: Set HKCU\Environment\windir to hijack path,
[*]   SilentCleanup scheduled task runs as elevated
[*] HKCU\Environment writable: Yes
[*] SilentCleanup task registered: Yes
[+] VIABLE -> uac-bypass silentcleanup <local_exe>

--- SSPI Datagram Contexts ---
[*] Technique: SSPI datagram-style auth context abuse for token theft
[*] OS build 19045 >= 17134: OK
[+] VIABLE -> uac-bypass sspidatagram <remote_file>

[...]

=== Summary ===
[*] Review [+] entries above for viable techniques
[*] Use 'uac-bypass <technique> ...' to execute
```

## Files

| File | Purpose |
|------|---------|
| `src/entry.c` | BOF source — all check logic |
| `bin/uaccheck.x64.o` | Compiled x64 object file |
| `uaccheck.py` | Havoc Python wrapper — registers subcommands |
| `UACCHECK.md` | This documentation |

## Relationship to UacBonanza

UacCheck is the **recon** companion to UacBonanza (the **action** module). The workflow is:

1. Run `uac-check all` to see which bypasses are viable
2. Pick a `[+] VIABLE` technique
3. Run the corresponding `uac-bypass <technique>` command

UacCheck never modifies the target — no files are written, no registry keys are changed, no COM objects are instantiated. It only reads.
