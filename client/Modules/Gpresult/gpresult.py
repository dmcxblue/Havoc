"""
Gpresult — RSoP reporter + domain GPO-ACE sweep.

Reimplements the useful core of `gpresult /R` directly in a BOF (no
gpresult.exe spawn): queries the RSoP WMI provider (root\\rsop\\user,
root\\rsop\\computer) for applied/filtered GPOs, session and security groups.

`gpresult domain` sweeps every GPO-related ACL the caller's token touches
across the domain — GPO objects, SYSVOL GPT DACLs, domain/OU/site gPLink
writes and WMI filters (see PLAN-DOMAIN.md).

Commands:
    gpresult             user + computer RSoP (matches gpresult /R)
    gpresult user        user settings only
    gpresult computer    computer settings only
    gpresult domain      domain-wide GPO ACE sweep for the current token
    gpresult domain -v   include read-only ACEs + the token SID list

Wire: int mode (0=all, 1=user, 2=computer); mode 3 carries a second int
(verbose flag).
"""

from havoc import Demon, RegisterCommand

BOF_PATH = "bin/gpresult.x64.o"

MODE_ALL      = 0
MODE_USER     = 1
MODE_COMPUTER = 2
MODE_DOMAIN   = 3

DOMAIN_ALIASES  = ("domain", "dom", "d")
VERBOSE_ALIASES = ("-v", "--verbose", "v")


def gpresult_cmd(demonID, *params):
    demon = Demon(demonID)

    if demon.ProcessArch == "x86":
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "gpresult BOF is x64-only")
        return False

    # gpresult domain [-v] — domain-wide GPO ACE sweep
    if params and params[0].lower() in DOMAIN_ALIASES:
        extra = [p.lower() for p in params[1:]]
        if any(p not in VERBOSE_ALIASES for p in extra):
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: gpresult domain [-v]")
            return False
        verbose = 1 if any(p in VERBOSE_ALIASES for p in extra) else 0

        packer = Packer()
        packer.addint(MODE_DOMAIN)
        packer.addint(verbose)

        TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
                                    "Tasked demon to run gpresult domain (GPO ACE sweep)")
        demon.InlineExecute(TaskID, "go", BOF_PATH, packer.getbuffer(), False)
        return TaskID

    if len(params) > 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: gpresult [user|computer|domain]")
        return False

    mode = MODE_ALL
    if len(params) == 1:
        a = params[0].lower()
        if a in ("user", "u"):
            mode = MODE_USER
        elif a in ("computer", "comp", "c"):
            mode = MODE_COMPUTER
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Usage: gpresult [user|computer|domain]")
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
    "Report RSoP (gpresult /R) or sweep every GPO ACE the caller's token holds across the domain (gpresult domain) — no gpresult.exe",
    0,
    "[user|computer|domain] [-v]",
    "domain",
)
