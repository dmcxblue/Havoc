# Havoc Module Development Guide

How to write a module for the Havoc client. This is the authoritative
pattern for this repo — every module under `client/Modules/` should
follow it. The companion `CUSTOM_MODULES.md` documents *what each module
does*; this file documents *how to build one correctly*.

A Havoc module is two pieces:

1. A **Python wrapper** (`.py`) that registers commands and packs args.
2. A **BOF** (`.o`, compiled from `entry.c`) that runs in the agent —
   only needed if the module executes native code.

---

## 1. Directory layout

```
client/Modules/<Name>/
├── <name>.py            # Python wrapper (command registration + arg packing)
├── src/entry.c          # the BOF (omit for Python-only modules)
├── include/             # optional local headers
├── bin/<name>.x64.o     # compiled BOF (committed, so it works out of the box)
└── <NAME>.md            # optional design/wire-format walkthrough
```

Python-only modules (no BOF) just need `<name>.py` and the registration.

---

## 2. Registering commands — and the help convention

Every command is registered with `havoc.RegisterCommand`. The C++ binding
signature is:

```c
RegisterCommand( function, module, command, description, behavior, usage, example, agent )
```

| Param        | Type | Purpose |
|--------------|------|---------|
| `function`   | callable | the Python handler `def cmd(demonID, *params)` |
| `module`     | str | module namespace (`""` for a global command, `"dotnet"` for `dotnet execute`, etc.) |
| `command`    | str | the command name users type |
| `description`| str | **one-line summary** — this is what `help` prints in the command list |
| `behavior`   | int | usually `0` (see `Behavior` flags in the client) |
| `usage`      | str | **full detailed help** — this is what `help <command>` prints |
| `example`    | str | a short example, shown with `help <command>` |
| `agent`      | str | keyword-only, defaults to `"Demon"` |

### The one rule that matters most

**`description` (the 4th arg) must be a single short line. The full
multi-line help goes in `usage` (the 6th arg).**

- `help` (no argument) → prints every command's `description` in a table.
  If you stuff the full help text into `description`, the whole `help`
  listing becomes an unreadable wall of text.
- `help <command>` → prints `usage` (and `example`) — the detailed docs.

**Correct** (see `nanorobeus.py`):

```python
RegisterCommand( kerberoast, "", "kerberoast",
    "Request TGS service tickets and emit them as crackable hashes",   # description (short)
    0,
    KERBEROAST_HELP,                                                   # usage (full help)
    "jnovoa" )                                                         # example
```

**Wrong** (the bug that motivated this doc):

```python
RegisterCommand( standin_cmd, "", "standin",
    STANDIN_HELP,                          # full help in `description` → floods `help`
    0,
    "--computer <name> ...",               # usage holds a stub instead
    "--computer Innsmouth --make" )
```

Put the detailed block (usage, options, examples, notes) in `usage`, keep
`description` to one sentence.

---

## 3. The Python wrapper

```python
from havoc import Demon, RegisterCommand, RegisterModule

def my_command(demonID, *params):
    demon  = Demon(demonID)
    packer = Packer()

    # validate args, then pack the wire format:
    packer.addstr("some string")
    packer.adduint32(123)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to ...")
    demon.InlineExecute(TaskID, "go", f"bin/mycommand.{demon.ProcessArch}.o",
                        packer.getbuffer(), False)
    return TaskID

RegisterCommand(my_command, "", "mycommand",
    "one-line summary", 0, "full help here", "example")
```

Points:

- `demon.ProcessArch` is `x64` or `x86` — use it in the `.o` path so both
  architectures load the right object.
- `Packer` is `client/Modules/Packer/packer.py`. The BOF unpacks the same
  order with `BeaconDataParse` + `BeaconDataExtract`/`BeaconDataInt`.
- Return the `TaskID` so the console can track the task.

---

## 4. The BOF (`entry.c`)

```c
#include "bofdefs.h"
#include "base.c"

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    char* s = BeaconDataExtract(&parser, NULL);
    int   n = BeaconDataInt(&parser);

    internal_printf("[*] got %s and %d\n", s, n);

    printoutput(TRUE);   // flush the buffered output
}
```

Conventions:

- `#include "../../RemoteOps/CS-Remote-OPs-BOF/src/common/{bofdefs.h,base.c}"`
  for `bofstart` / `internal_printf` / `printoutput` / `intAlloc` / `intFree`.
- Declare any WinAPI you need with the `$`-routed DFR symbols, e.g.
  `DECLSPEC_IMPORT ... KERNEL32$CopyFileA(...)`. Never call libc `memset`/
  `memcpy` directly in a BOF — route them through `MSVCRT$` (`-fno-builtin`)
  or the DFR symbol lookup will fail at load time.
- Always `printoutput(TRUE)` at the end of `go` to flush the output buffer.

---

## 5. Build integration

1. Add a compile rule to the top-level `makefile` under `bof-build`,
   mirroring an existing block (e.g. `Clipboard` / `Icacls`). Typical line:

   ```make
   x86_64-w64-mingw32-gcc -Os -c entry.c -DBOF -I ../../common -o bin/<name>.x64.o
   ```

2. Add the `.py` path to `client/config.toml → [scripts].files` so the
   client loads the wrapper on startup.

3. Rebuild with `make bof-build` (or `make client-build`), restart the
   client, and test the wire format.

### Gotcha — `g++` stack probes

C++ BOFs (WMI, COM) with big stack buffers need `-mno-stack-arg-probe`,
otherwise `g++` emits `___chkstk_ms` (libgcc) which the demon BOF loader
can't resolve. See `WmiSubscriptions` / `Gpresult` for the working pattern.

---

## 6. Checklist for a new module

- [ ] `<name>.py` registers the command with a **short `description`** and
      **full help in `usage`**.
- [ ] `.o` path uses `demon.ProcessArch`.
- [ ] BOF flushes with `printoutput(TRUE)`.
- [ ] Compiled `.o` is committed to `bin/`.
- [ ] `makefile` rule added; `config.toml` updated.
- [ ] Restart client, run `help` (list shows one-liner) and
      `help <command>` (shows detailed usage), then run the command.
