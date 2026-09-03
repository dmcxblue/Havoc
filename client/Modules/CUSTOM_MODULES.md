# Havoc Custom Modules

This file documents every **custom** module maintained locally in this
`client/Modules/` tree — i.e. modules **not** shipped by upstream
`HavocFramework/Modules`. Each one is:

- registered in `client/config.toml → [scripts].files`,
- built (when native code is involved) by the top-level `makefile`
  `bof-build` target so a fresh clone rebuilds everything with
  `make client-build`,
- force-added to the top Havoc repo so the working set survives a
  `git pull` even though `client/Modules/*` is gitignored.

For upstream modules (SituationalAwareness, RemoteOps proper, nanodump,
etc.) see the upstream `HavocFramework/Modules` documentation. Never
edit the vendored `CS-*-BOF/` submodule trees — extend via a sibling
wrapper (see `RemoteOpsExtra` below).

Wire format for every BOF listed below: the Python wrapper serialises
args with the standard `Packer` class (`client/Modules/Packer/packer.py`)
and passes them to `demon.InlineExecute("go", "bin/<name>.<arch>.o",
buffer, False)`. The BOF's `go(char *args, int len)` uses
`BeaconDataParse` + `BeaconDataExtract`/`BeaconDataInt` to unpack. All
BOFs are compiled x64-only unless stated otherwise, using
`x86_64-w64-mingw32-gcc -Os -c entry.c -DBOF` (some with `-fno-builtin`
for MSVCRT$-routed `memset`/`memcpy` — see the DFR-symbols memory).

---

## PrivKit — `client/Modules/PrivKit/`

**Purpose.** 11 automated privilege-escalation checks, aggregated into a
single BOF that dispatches per subcommand. Port of
`mertdas/PrivKit` (originally a Cobalt Strike BOF) to Havoc, with fixes
for correctness and output handling.

**Subcommands** (all registered in the `privkit` module namespace):

| Command                    | What it checks                                                            |
|----------------------------|---------------------------------------------------------------------------|
| `privkit all`              | Runs every check below                                                    |
| `privkit alwaysinstall`    | `HKLM\...\Installer\AlwaysInstallElevated` + HKCU counterpart both = 1    |
| `privkit unquoted`         | Service `ImagePath` with unquoted path containing spaces                  |
| `privkit modifiable`       | Service DACL grants `SERVICE_CHANGE_CONFIG` to a group in the user token  |
| `privkit autologon`        | `HKLM\...\Winlogon\DefaultPassword` present                               |
| `privkit credmanager`      | Enumerates Windows Credential Manager entries                             |
| `privkit hijackablepath`   | User-writable directories in `PATH`                                       |
| `privkit modifiableautorun`| Autorun entries whose binaries are user-writable                          |
| `privkit tokenprivileges`  | Lists enabled privileges on the current token                             |
| `privkit powershellhistory`| Reads `%APPDATA%\...\ConsoleHost_history.txt` for secrets                 |
| `privkit uac`              | UAC configuration (level / EnableLUA / ConsentPromptBehaviorAdmin)        |
| `privkit writablesvc`      | File-level DACL of each service binary — is it writable by the user?      |

**How the DACL-based checks work.** Both `modifiable` (service object)
and `writablesvc` (file object) walk the DACL manually via
`GetSecurityDescriptorDacl` + `GetAce`, then decide membership by
calling `CheckTokenMembership(NULL, ...)`. Two subtle traps historically
bit these:

1. `CheckTokenMembership` **requires an impersonation token**; passing
   the primary token from `OpenProcessToken` silently returns `FALSE`
   for group SIDs on many builds. Passing `NULL` makes Windows use the
   thread's token, auto-duplicating the primary token into an
   impersonation token internally.
2. `if (mask & SERVICE_ALL_ACCESS)` was used as a single-bit test, but
   `SERVICE_ALL_ACCESS = 0x000F01FF` is a *combined* mask covering
   every service right including read-only ones. Using `&` fires on
   any ACE granting even `ReadControl`. Correct form:
   `(mask & SERVICE_ALL_ACCESS) == SERVICE_ALL_ACCESS`.

Together these two bugs produced either "no findings" (bug 1 hid bug 2)
or "every service is vulnerable" (fixing only bug 1). Both are fixed;
see `client/Modules/PrivKit/repo/src/PrivKitAll/entry.c`
`HasModifyRights` and `CheckSidInToken`.

**`writablesvc` also handles**:
- **NULL DACL** — `bDaclPresent && pDacl == NULL` grants everyone all
  access; flagged as `[+] WRITABLE (NULL DACL)`.
- **Explicit deny ACEs** — a pre-pass walks `ACCESS_DENIED_ACE_TYPE`
  entries; if any deny with write rights matches the token, the allow
  ACE pass is skipped, avoiding the canonical-order false positive.
- **Uses `GetFileSecurityA` DACL analysis** rather than
  `CreateFileA(GENERIC_WRITE)` — the latter fails on running service
  binaries because Windows locks mapped images against writable
  handles, even when the ACL would allow it.

**Files.**
- `privkit.py` — dispatcher (12 registrations, subcommand namespace)
- `repo/src/PrivKitAll/entry.c` — the merged all-checks BOF (~1900 lines)
- `repo/src/common/{bofdefs.h,base.c,beacon.h}` — vendored from mertdas
- `bin/PrivKitAll.x64.o` — compiled with `-fno-builtin` because bare
  `memset`/`memcpy` from libc must go through `MSVCRT$` DFR symbols
  (see the `feedback_bof_dfr_symbols` memory).

---

## Icacls — `client/Modules/Icacls/`

**Purpose.** Read a file or directory's DACL in human-readable form.
The upstream CS-Situational-Awareness `cacls` BOF outputs cryptic
single-letter rights (`F`, `M`, `R`); this one writes full words and
gets the "Applies to" semantics right for files vs directories.

**Command.** `icacls <path>`

**How it works.** Calls
`GetNamedSecurityInfoA(path, SE_FILE_OBJECT, OWNER|DACL)`, walks each
ACE with `GetAce`, resolves the SID via `LookupAccountSidA` (falling
back to `ConvertSidToStringSidA`), and prints:

- SID as `DOMAIN\User` (or raw SID)
- ACE type: `Allow` / `Deny` / `Type=0xNN` for unknown
- Permissions decoded via `PrintPermissions`:
  - Prefixed with the classic letter for scanability plus the full
    Windows Explorer term: `F  (Full Control)`, `M  (Modify)`,
    `RX (Read & Execute)`, `R (Read)`, `W (Write)`,
    `GA/GX/GW/GR (Generic *)`, or `Special (0x%08X)`.
- Inherited: `Yes` / `No`
- **Applies to** — computed based on whether the target is a directory
  (via `GetFileAttributesA & FILE_ATTRIBUTE_DIRECTORY`):
  - files → `This file` (or `This file (unexpected flags=0x%02X)` if
    an ACE against a file has CI/OI/IO set, which is rare/broken)
  - directories → the classic `This folder only`,
    `This folder, subfolders, and files`, `Subfolders only`, etc.

**Files.**
- `icacls.py` — registers `icacls`
- `src/entry.c` — inline DECLSPEC_IMPORTs (no RemoteOps dep)
- `bin/icacls.x64.o`

---

## Copy — `client/Modules/Copy/`

**Purpose.** Copy a single file, Windows-style, from a BOF. Always
overwrites (a BOF can't prompt like `cmd.exe` does, and asking the
operator to type `/y` was dead syntax).

**Command.** `copy <source> <destination>`

**How it works.** Calls `KERNEL32$CopyFileA(source, dest, FALSE)`
(third arg `bFailIfExists = FALSE` → always overwrite). Before the
copy, checks the destination attributes:

- If `dest` exists and is a directory (`FILE_ATTRIBUTE_DIRECTORY`),
  appends `basename(source)` so `copy C:\a.txt C:\subdir` writes to
  `C:\subdir\a.txt` (matching `cmd.exe`'s copy semantics).
- Otherwise, `dest` is treated as the exact target path.

Prints friendly decoding for the common `GetLastError` values:
`FILE_NOT_FOUND` (2), `PATH_NOT_FOUND` (3), `ACCESS_DENIED` (5),
`SHARING_VIOLATION` (32).

**Files.**
- `copy.py` — registers `copy`
- `src/entry.c` — uses RemoteOps common headers
- `bin/copy.x64.o`

---

## ScSdshow — `client/Modules/ScSdshow/`

**Purpose.** Havoc equivalent of `sc.exe sdshow <service>`. Windows'
built-in gives you just the raw SDDL blob; this BOF prints the SDDL
verbatim **plus** a parsed, friendly view — Owner/Group + each ACE
with type, resolved SID, and every right listed as
`<API name> (<SDDL abbrev>)`.

**Command.** `sc_sdshow <service_name>`

**How it works.**
1. `OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT)`.
2. `OpenServiceA(hSCM, name, READ_CONTROL)` — needs only read of the
   security descriptor.
3. `QueryServiceObjectSecurity` twice (once for size, once with buffer).
4. `ConvertSecurityDescriptorToStringSecurityDescriptorA` for the raw
   SDDL — matches `sc.exe sdshow` output byte-for-byte, useful for
   cross-referencing.
5. `GetSecurityDescriptorOwner/Group/Dacl`, then walks each ACE.
6. **`PrintServiceRights`** decodes the mask using a lookup table that
   preserves both the SDDL abbreviation (`CC`, `DC`, `LC`, `SW`, `RP`,
   `WP`, `DT`, `LO`, `CR`, `SD`, `RC`, `WD`, `WO`, `SY`) and the human
   name (`QueryConfig`, `ChangeConfig`, `QueryStatus`, `Start`, `Stop`,
   `Delete`, `WriteDac`, ...). Short-circuits to `Full Control` when
   `(mask & SERVICE_ALL_ACCESS) == SERVICE_ALL_ACCESS` **and** all
   standard rights are also set — same `==` discipline as PrivKit.
7. **NULL DACL** flagged explicitly (`grants everyone all access`).

DACL only — SACL requires `SeSecurityPrivilege` and `sc.exe sdshow`
also skips it by default.

**Files.**
- `sc_sdshow.py` — registers `sc_sdshow`
- `src/entry.c` — uses RemoteOps common headers
- `bin/sc_sdshow.x64.o`

---

## GhostTask — `client/Modules/GhostTask/`

**Purpose.** Modify a Windows scheduled task's action binary by writing
directly to the registry, bypassing Task Scheduler API — which means
**no Event ID 4702** (the "task modified" audit event that fires only
on API-driven edits). Port of `dmcxblue/SharpGhostTask` C# tool.

**Commands.**
```
ghosttask --show                              # list all tasks recursively
ghosttask <task_name> <target_binary>         # ghost a task
```

**How it works.**

*List mode.* Recursively enumerates
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`
via `RegOpenKeyExA` + `RegEnumKeyExA`, depth-capped at 16. Any subkey
carrying an `Id` value is a real task (folders don't have one) and is
printed as its full path (`\Microsoft\Windows\...\TaskName`).

*Ghost mode.*
1. Reads the target task's GUID from `Tree\<name>\Id` (REG_SZ).
2. Opens `Tasks\<GUID>` for write. **Two attempts**:
   - **Attempt 1** — `KEY_SET_VALUE`. Succeeds when running as SYSTEM.
   - **On `ERROR_ACCESS_DENIED`, attempt 2** — enable
     `SeBackupPrivilege` + `SeRestorePrivilege` via
     `AdjustTokenPrivileges`, then reopen with
     `REG_OPTION_BACKUP_RESTORE` (which ignores `samDesired` and grants
     backup/restore access, bypassing the DACL that denies writes to
     `BUILTIN\Administrators` on `TaskCache\Tasks`). Prints
     `[*] Elevated via SeBackupPrivilege + SeRestorePrivilege` so the
     operator sees which path fired.
   - If neither privilege can be enabled → plain user → clear error.
3. Writes a hand-crafted `Actions` `REG_BINARY` blob:

   ```
   [ 0- 1]  03 00                     version marker
   [ 2- 3]  0C 00                     author-field length (12 bytes)
   [ 4- 5]  00 00                     padding
   [ 6-17]  A\0 u\0 t\0 h\0 o\0 r\0   UTF-16 LE "Author"
   [18-19]  66 66                     task-name section marker (empty here)
   [20-23]  00 00 00 00               padding
   [24-27]  NN NN NN NN               target-path byte length (LE, no null)
   [28..]   target path bytes (UTF-16 LE, no trailing null)
   [tail]   00 * 10                   trailer
   ```

Faithful byte-for-byte port of the SharpGhostTask blob layout.

**Requires.** SYSTEM, or Administrator (auto-elevates as above). The
task fires the new binary on its next scheduled trigger — no immediate
side effect.

**Files.**
- `ghosttask.py` — registers `ghosttask`
- `src/entry.c` — uses RemoteOps common headers
- `bin/ghosttask.x64.o`

---

## RemoteOpsExtra — `client/Modules/RemoteOps/RemoteOpsExtra.py`

**Purpose.** Sibling wrapper that registers the 15 CS-Remote-OPs-BOF
commands that upstream `RemoteOps.py` does *not* already register.
Upstream is left untouched so future `HavocFramework/Modules` updates
need no manual merge. The 12 Injection/ BOFs are intentionally
skipped (they overlap with Havoc's own injection facilities;
`Injection/clipboard` would collide with the custom `Clipboard` module).

**Commands registered:**

| Command             | What it does                                                    |
|---------------------|-----------------------------------------------------------------|
| `chromeKey`         | Extract Chrome master key from DPAPI                            |
| `get_priv`          | Enable a Windows privilege on the current token                 |
| `office_tokens`     | Dump MS Office access tokens from a target process              |
| `procdump`          | MiniDump a process via dbghelp                                  |
| `ProcessDestroy`    | Close a specific handle in a remote process                     |
| `ProcessListHandles`| List all open handles for a target PID                          |
| `sc_config`         | Reconfigure a service (binary path / start mode)                |
| `sc_failure`        | Set failure actions for a service                               |
| `schtaskscreate`    | Create a scheduled task from a local XML file                   |
| `schtasksdelete`    | Delete a scheduled task or folder                               |
| `schtasksrun`       | Run an existing scheduled task on demand                        |
| `schtasksstop`      | Stop a running scheduled task                                   |
| `shspawnas`         | Spawn shellcode as another user via `CreateProcessWithLogon`    |
| `suspendresume`     | Suspend or resume all threads of a target process               |
| `unexpireuser`      | Clear the account-expiration flag on a user                     |

**How it works.** Each wrapper validates arg types (int/short/wstr/
bytes), reads local files when needed (XML for `schtaskscreate`,
shellcode for `shspawnas`), packs with the standard `Packer`, and
calls `InlineExecute("go", f"bin/<name>.{ProcessArch}.o", ...)` —
loading from `client/Modules/RemoteOps/bin/`, the same directory
upstream `RemoteOps.py` uses.

**Build.** The top-level `makefile`'s `bof-build` target has a shell
loop over `$(REMOTEOPS_EXTRA_BOFS)` that compiles each BOF x64+x86
from `CS-Remote-OPs-BOF/src/Remote/<name>/entry.c` into
`client/Modules/RemoteOps/bin/`. The vendored source tree is only
read from, never modified.

**Not included.** `lastpass` — its wire format is a structured data
blob that needs LastPass-specific serialization; a naive stub would
misbehave.

---

## Clipboard — `client/Modules/Clipboard/`

**Purpose.** Read the current clipboard text (Unicode or ANSI).

**Command.** `clipboard`

**How it works.**
1. `OpenClipboard(NULL)`.
2. Prefers `CF_UNICODETEXT`; falls back to `CF_TEXT` if only that's
   present.
3. `GetClipboardData(fmt)` → `GlobalLock` to read the memory,
   `GlobalUnlock` when done.
4. UTF-16 text is converted to UTF-8 via `Utf16ToUtf8` (from RemoteOps
   `base.c`) before display.
5. `CloseClipboard()`.

Silent if the clipboard is empty or holds a non-text format.

**Files.**
- `clipboard.py` — registers `clipboard`
- `src/entry.c` — uses RemoteOps common headers
- `bin/clipboard.x64.o`

---

## Keylogger — `client/Modules/Keylogger/`

**Purpose.** Foreground-window keystroke logger. Writes to the demon
output stream; the client renders it live in the console.

**How it works.** Standard `SetWindowsHookEx(WH_KEYBOARD_LL, ...)`
loop with per-window heading emission. **Tracks the foreground
window's `HWND`, not its title text**, so title changes on the same
window don't produce a header-per-keystroke storm (this was a real
bug — see commit `e647d53`).

**Files.**
- `keylogger.py`
- `src/entry.c`
- `bin/keylogger.x64.o`

---

## LiveDesktop — `client/Modules/LiveDesktop/`

**Purpose.** HVNC-style live desktop capture. Streams frames from the
target's session-0 or user-session desktop back to a Qt viewer widget
on the client. Fully functional — real desktop capture, LZNT1 frame
compression, diff-frame updates.

**How it works** (client side). A `LiveDesktopWidget` Qt widget opens
alongside the demon console, subscribes to frame events over the
teamserver websocket, and paints incoming diff frames onto a
`QPixmap`. The BOF-side capture uses GDI (`BitBlt`) plus LZNT1
compression for bandwidth; unchanged tiles are skipped between frames.

**Files.**
- `livedesktop.py`
- `src/entry.c` — compiled with `-fno-builtin`
- `bin/livedesktop.x64.o`
- Client-side viewer: `client/{include,src}/UserInterface/Widgets/LiveDesktopWidget.{hpp,cc}`

---

## Building

Everything in this file is compiled by the top-level `makefile`
`bof-build` target, invoked automatically by `make client-build`
(and `make client-build-mac`):

```bash
make bof-build          # just the BOFs (fast)
make client-build       # full client incl. BOFs
```

The Python `.py` wrappers are loaded fresh on client start — no
compilation needed; just restart the client to pick up any change.

## Adding a new custom module

Follow the pattern used by every module above:

1. `client/Modules/<Name>/src/entry.c`, `bin/<name>.x64.o`,
   `<name>.py` — directory layout.
2. `<name>.py` uses `havoc.RegisterCommand` and packs args with
   `Packer` (see `client/Modules/Packer/packer.py`).
3. The `.c` file `#include`s
   `../../RemoteOps/CS-Remote-OPs-BOF/src/common/{bofdefs.h,base.c}`
   for `bofstart`/`internal_printf`/`printoutput`/`intAlloc`/`intFree`
   and standalone-declares any WinAPI it needs as
   `DECLSPEC_IMPORT ... KERNEL32$Foo(...)` / `ADVAPI32$Foo(...)`.
4. Add a build rule to the top-level `makefile` under `bof-build`
   (mirror the `Clipboard`/`Icacls` blocks).
5. Add the `.py` path to `client/config.toml → [scripts].files`.
6. Force-add the new files to the top Havoc repo with `git add -f`
   since `client/Modules/*` is gitignored.

Test the wire format matches: rebuild, restart the client, run the
command, watch the demon output.
