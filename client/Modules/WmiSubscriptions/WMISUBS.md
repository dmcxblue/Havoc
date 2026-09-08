# WmiSubscriptions — WMI Event Subscription Persistence (T1546.003)

A Havoc BOF module that installs, enumerates, and removes **permanent WMI
event subscriptions** for persistence. A subscription is a
`CommandLineEventConsumer` + `__EventFilter` + `__FilterToConsumerBinding`
triple (plus an optional `__IntervalTimerInstruction`) living in the
`root\subscription` WMI namespace; once installed it survives reboots and
WMI itself fires the operator's command whenever the trigger fires — no
beacon callback needed.

## Why this module

The tree already has a WMI BOF (`Jump-exec/WMI/EventSub`) but it is a
**lateral-movement** tool: it connects to a *remote* `root\subscription`
namespace, drops a throwaway `ActiveScriptEventConsumer` (VBScript), waits
11 seconds for it to fire, then deletes everything. That is great for
"run once on a remote box now", useless for "stay resident on this box".

WmiSubscriptions is the **persistence** counterpart:

| | EventSub (existing) | WmiSubscriptions (this) |
|---|---|---|
| Target | remote host (`\\host\root\subscription`) | local host |
| Consumer | `ActiveScriptEventConsumer` (VBS) | `CommandLineEventConsumer` (any cmdline) |
| Lifetime | 11 s, then self-deletes | permanent |
| Trigger | fixed interval timer | startup / logon / process / interval / custom WQL |
| Goal | lateral movement | T1546.003 persistence |

## Commands

```
wmisubs list
wmisubs create <name> <command> --trigger <t> [--timer-id <id>] [--interval <sec>]
wmisubs remove <name> [--timer-id <id>]
wmisubs clean
```

### Triggers

The Python wrapper resolves a friendly trigger spec to WQL **before** the
BOF runs, so the BOF only ever receives a finished query string:

| Spec | WQL | Notes |
|------|-----|-------|
| `startup` | `__InstanceModificationEvent` on `Win32_PerfFormattedData_PerfOS_System` with `SystemUpTime` 240–325 s | fires ~4–5 min after boot, the classic WMI-persistence boot trigger |
| `logon` | `__InstanceCreationEvent` on `Win32_LogonSession` | fires on each interactive logon |
| `process:<exe>` | `Win32_ProcessStartTrace WHERE ProcessName = '<exe>'` | fires when a specific process starts |
| `interval:<sec>` | `__TimerEvent WHERE TimerId="<id>"` + a matching `__IntervalTimerInstruction` | fixed-period beaconing |
| `wql:"<query>"` | raw custom query | escape hatches |

`interval:` triggers additionally create an `__IntervalTimerInstruction`
instance carrying `IntervalBetweenEvents` (ms). The timer id defaults to
`<name>_timer` and is overridable with `--timer-id`.

### Wire protocol

The wrapper packs a mode int followed by mode-specific UTF-16LE strings
(`Packer.addWstr`) and ints; the BOF unpacks with `BeaconDataParse` +
`BeaconDataExtract`/`BeaconDataInt`. `addWstr` is used (not `addstr`)
because every WMI property must be a wide string.

| Mode | Subcommand | Payload |
|------|-----------|---------|
| 0 | `list` | *(none)* |
| 1 | `create` | wstr name, wstr commandline, wstr query, wstr timerId, int intervalMs |
| 2 | `remove` | wstr name, wstr timerId |
| 3 | `clean` | *(none)* |

## Architecture

```
wmisubscriptions.py ──(mode + wstr args)──> wmisubscriptions.cpp (BOF)
                                              │
                                              ├── CoInitializeEx
                                              ├── CoCreateInstance(WbemLocator)
                                              ├── ConnectServer(root\subscription)
                                              ├── CoSetProxyBlanket
                                              │
                                              ├─ mode 0 → DoList    (ExecQuery + print)
                                              ├─ mode 1 → DoCreate  (PutInstance x3/x4)
                                              ├─ mode 2 → DoRemove  (DeleteInstance x3/x4)
                                              └─ mode 3 → DoClean   (DeleteInstance all)
```

### Creation order (mode 1)

1. `GetObject("__EventFilter")` → `SpawnInstance` → set `Name`,
   `QueryLanguage="WQL"`, `Query` → `PutInstance(CREATE_OR_UPDATE)`.
2. `GetObject("CommandLineEventConsumer")` → `SpawnInstance` → set `Name`,
   `CommandLineTemplate` → `PutInstance`.
3. `GetObject("__FilterToConsumerBinding")` → `SpawnInstance` → set
   `Consumer` and `Filter` as **CIM_REFERENCE** object paths
   (`__EventFilter.Name="…"` / `CommandLineEventConsumer.Name="…"`) →
   `PutInstance`.
4. If `timerId` is non-empty, also `GetObject("__IntervalTimerInstruction")`
   → `SpawnInstance` → set `TimerId` + `IntervalBetweenEvents` →
   `PutInstance`.

`WBEM_FLAG_CREATE_OR_UPDATE` means re-running `create` with the same name
idempotently overwrites the existing subscription.

### Deletion order (mode 2 / 3)

The **binding is deleted first**, then the consumer, then the filter, then
(optionally) the timer. This avoids leaving a dangling binding that
references a filter/consumer that no longer exists. `DeleteInstance` takes
the fully-escaped `__RELPATH` string:

```
__FilterToConsumerBinding.Consumer="CommandLineEventConsumer.Name=\"<name>\"",Filter="__EventFilter.Name=\"<name>\""
```

`clean` enumerates each of the five classes with `ExecQuery`, collects each
instance's `__RELPATH`, and `DeleteInstance`s them (bindings first).

## Build

```
x86_64-w64-mingw32-g++ -c -Os -w -mno-stack-arg-probe \
    src/wmisubscriptions.cpp -I include -o bin/wmisubscriptions.x64.o
```

- **g++ not gcc** — the WMI COM interfaces come from `wbemcli.h`, C++.
- **`-mno-stack-arg-probe` is load-bearing.** The BOF keeps several large
  wide-string buffers on the stack (`wchar_t path[2048]`, `ref[1024]`).
  Without this flag g++ emits calls to `___chkstk_ms` (libgcc's stack-probe
  helper); the demon's BOF loader has no such symbol, so the object would
  fail to resolve at load time. The flag removes the probe, leaving only
  `__imp_*` import symbols, which the loader *does* resolve.
- The module `makefile` mirrors `Bitsadmin/makefile`; the top-level Havoc
  `makefile` `bof-build` target also compiles it on every `client-build`.

## Undefined-symbol contract (verified)

After the build, `nm -u` must show **only** `__imp_*` imports:

```
__imp_BeaconDataExtract  __imp_BeaconDataInt  __imp_BeaconDataParse
__imp_BeaconOutput
__imp_KERNEL32$GetProcessHeap  __imp_KERNEL32$HeapAlloc
__imp_KERNEL32$HeapFree  __imp_KERNEL32$WideCharToMultiByte
__imp_MSVCRT$memcpy  __imp_MSVCRT$vsnprintf
__imp_OLE32$CLSIDFromString  __imp_OLE32$CoCreateInstance
__imp_OLE32$CoInitializeEx  __imp_OLE32$CoSetProxyBlanket
__imp_OLE32$CoUninitialize  __imp_OLE32$IIDFromString
__imp_OLEAUT32$VariantClear  __imp_OLEAUT32$VariantInit
```

No `___chkstk_ms`, no `MSVCRT$` symbols, no `std::` mangled names — the
C++ is written in a deliberately C-ish style (no STL, no exceptions, no
RTTI) so the object is self-contained aside from the imports above.

Note: `__imp_MSVCRT$vsnprintf` / `__imp_MSVCRT$memcpy` resolve to
`GetProcAddress(msvcrt, "vsnprintf"/"memcpy")` via the demon's `$`-split
symbol loader — the same DFR symbols `base.c` uses, so they are safe.

## Output buffering (single chunk)

The BOF must NOT call `BeaconPrintf` — that emits one `BeaconOutput` per
line and the demon delivers the result as a burst of `[+] Received Output`
fragments. Instead it buffers every line with an internal `bprintf()` and
flushes **once** at the end of `go()`:

```
bprintf(...)  →  append to a heap 8 KiB buffer (g_out)
...
bflush()      →  BeaconOutput(CALLBACK_OUTPUT, g_out, g_outLen)   // exactly one call
```

This mirrors the C modules' `internal_printf` + `printoutput(TRUE)` and is
why their output arrives as a single chunk. Two implementation traps:

1. The global buffer pointer/length are initialized to **non-zero
   sentinels** (`(char*)1` / `1`) so they land in `.data`, not `.bss` —
   the BOF loader does not zero `.bss` (same reason `base.c` uses
   `char * output = (char*)1`). `go()` allocates the real buffer and
   resets the length before the first `bprintf()`.
2. If a single line would overflow the buffer, `bprintf()` flushes what it
   has first (same as `internal_printf`), so an unusually large listing
   still arrives intact, just as a couple of chunks instead of dozens.



## OPSEC notes

- Subscriptions are **persistent and visible** to defenders:
  `Get-WmiObject -Namespace root\subscription -Class __EventFilter` (and
  the other four classes) reveals them. Clean up with `wmisubs remove`
  or `wmisubs clean` when done.
- Creation/removal is logged via the WMI-Activity operational log
  (Event IDs 5861 for permanent-event-subscription registration); this is
  inherent to the technique and not a bug.
- The `CommandLineEventConsumer` runs the command as **SYSTEM**, so the
  operator's payload inherits SYSTEM privileges when the subscription
  fires.
