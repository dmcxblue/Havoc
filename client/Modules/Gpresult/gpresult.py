"""
Gpresult — Resultant Set of Policy (RSoP) reporter.

Reimplements the useful core of `gpresult /R` directly in a BOF (no
gpresult.exe spawn). Queries the RSoP WMI provider in root\\rsop\\user and
root\\rsop\\computer for the session, applied/filtered GPOs, and security
groups, plus OS/user/domain header info via WinAPI.

Commands:
    gpresult             user + computer RSoP (matches gpresult /R)
    gpresult user        user settings only
    gpresult computer    computer settings only

Wire: single int mode (0=all, 1=user, 2=computer).
"""

from havoc import Demon, RegisterCommand

BOF_PATH = "bin/gpresult.x64.o"

MODE_ALL      = 0
MODE_USER     = 1
MODE_COMPUTER = 2


def gpresult_cmd(demonID, *params):
    demon = Demon(demonID)

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "gpresult BOF is x64-only")
        return False

    if len(params) > 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: gpresult [user|computer]")
        return False

    mode = MODE_ALL
    if len(params) == 1:
        a = params[0].lower()
        if a in ("user", "u"):
            mode = MODE_USER
        elif a in ("computer", "comp", "c"):
            mode = MODE_COMPUTER
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: gpresult [user|computer]")
            return False

    packer = Packer()
    packer.addint(mode)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to run gpresult (RSOP)")
    demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
    return TaskID


RegisterCommand(
    gpresult_cmd,
    "",
    "gpresult",
    "Report Resultant Set of Policy (RSoP) — applied/filtered GPOs, security groups, OS/domain info (no gpresult.exe)",
    0,
    "[user|computer]",
    "user",
)
